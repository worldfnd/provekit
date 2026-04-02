package circuit

import (
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"reilabs/whir-verifier-circuit/app/common"
	"reilabs/whir-verifier-circuit/app/utilities"
	"reilabs/whir-verifier-circuit/app/whir"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	gnark_nimue "github.com/reilabs/gnark-nimue"
)

type NimueInit = gnark_nimue.NimueInit

type Circuit struct {
	InitializationData NimueInit
	LogNumConstraints  int

	SessionID                    [32]uints.U8 `gnark:",public"`
	Transcript                   []uints.U8   `gnark:",public"`
	BlindingCommitmentWhirConfig WHIRParams
	BlindedCommitmentWhirConfig  WHIRParams
	NumChallenges                int
	W1Size                       int
	PublicInputs                 PublicInputs

	// Evaluation hints from prover (prover_hint_ark, not transcript-bound).
	// [az_at_alpha, bz_at_alpha, cz_at_alpha] for commitment 1 (or single commitment).
	Evaluations []frontend.Variable
	// [az_at_alpha, bz_at_alpha, cz_at_alpha] for commitment 2 (dual mode only).
	Evaluations2 []frontend.Variable
	// Public input evaluation hint (only used when PublicInputs is non-empty).
	PublicEval frontend.Variable

	// Merkle proof data for WHIR commitment verification (commitment 1 / single).
	BlindedMerkleData  whir.WhirMerkleData
	BlindingMerkleData whir.WhirMerkleData
	// Merkle proof data for commitment 2 (dual mode only).
	BlindedMerkleData2  whir.WhirMerkleData
	BlindingMerkleData2 whir.WhirMerkleData

	// R1CS matrices as sparse cell lists. Used to compute the weight MLE
	// evaluations for the FinalClaim binding check.
	MatrixA []MatrixCell
	MatrixB []MatrixCell
	MatrixC []MatrixCell
}

type Commitment struct {
	RootHash          frontend.Variable
	InitialOODQueries []frontend.Variable
	InitialOODAnswers [][]frontend.Variable
}

func (circuit *Circuit) Define(api frontend.API) error {
	sc, nimue, uapi, err := initializeComponents(api, circuit)
	if err != nil {
		return err
	}

	// ---------------------------------------------------------------
	// 1. Parse commitment 1 (witness polynomial)
	// ---------------------------------------------------------------
	blindedCommitments, blindingCommitment, err := zkWHIRCommitmentParsing(api, nimue, circuit.BlindedCommitmentWhirConfig, circuit.BlindingCommitmentWhirConfig, 1)
	api.Println("blindedCommitments", blindedCommitments)
	api.Println("blindingCommitment", blindingCommitment)
	if err != nil {
		return err
	}
	numPolynomials := 1
	isDualMode := circuit.NumChallenges > 0

	// ---------------------------------------------------------------
	// 2. If dual mode: squeeze logup challenges, parse commitment 2
	// ---------------------------------------------------------------
	var blindedCommitments2 []Commitment
	var blindingCommitment2 Commitment
	if isDualMode {
		logupChallenges := make([]frontend.Variable, circuit.NumChallenges)
		if err = nimue.FillChallengeScalars(logupChallenges); err != nil {
			return err
		}

		blindedCommitments2, blindingCommitment2, err = zkWHIRCommitmentParsing(api, nimue, circuit.BlindedCommitmentWhirConfig, circuit.BlindingCommitmentWhirConfig, 1)
		api.Println("blindedCommitments2", blindedCommitments2)
		api.Println("blindingCommitment2", blindingCommitment2)
		if err != nil {
			return err
		}
	}

	// ---------------------------------------------------------------
	// 3. ZK sumcheck
	// ---------------------------------------------------------------
	tRand, alpha, fAtAlpha, blindingEval, err := runZKSumcheck(api, sc, uapi, circuit, nimue, frontend.Variable(0), circuit.LogNumConstraints, 4)
	if err != nil {
		return err
	}
	api.Println("tRand", tRand)
	api.Println("alpha", alpha)
	api.Println("fAtAlpha", fAtAlpha)
	api.Println("blindingEval", blindingEval)

	// ---------------------------------------------------------------
	// 4. Public inputs hash check + x challenge
	// ---------------------------------------------------------------
	err = publicInputsHashCheck(api, sc, nimue, circuit.PublicInputs)
	if err != nil {
		return err
	}

	publicWeightsChallenge := make([]frontend.Variable, 1)
	if err := nimue.FillChallengeScalars(publicWeightsChallenge); err != nil {
		return fmt.Errorf("failed to read public weights challenge: %w", err)
	}
	api.Println("publicWeightsChallenge", publicWeightsChallenge)

	// ---------------------------------------------------------------
	// 5. Read evaluation hints
	// ---------------------------------------------------------------
	if len(circuit.Evaluations) < 3 {
		return fmt.Errorf("circuit.Evaluations must have at least 3 elements, got %d", len(circuit.Evaluations))
	}
	evals1Az := circuit.Evaluations[0]
	evals1Bz := circuit.Evaluations[1]
	evals1Cz := circuit.Evaluations[2]
	api.Println("evals1Az", evals1Az)
	api.Println("evals1Bz", evals1Bz)
	api.Println("evals1Cz", evals1Cz)

	hasPublicInputs := !circuit.PublicInputs.IsEmpty()

	// ---------------------------------------------------------------
	// 6. WHIR verification for commitment 1
	// ---------------------------------------------------------------
	{
		var whirEvaluations []frontend.Variable
		if hasPublicInputs {
			api.Println("publicEval", circuit.PublicEval)
			whirEvaluations = []frontend.Variable{circuit.PublicEval, evals1Az, evals1Bz, evals1Cz, blindingEval}
		} else {
			whirEvaluations = []frontend.Variable{evals1Az, evals1Bz, evals1Cz, blindingEval}
		}

		weightsLen := 4
		if hasPublicInputs {
			weightsLen = 5
		}

		blindedCommitmentNimue := ParsedCommitmentNimue{
			Root:       blindedCommitments[0].RootHash,
			OodPoints:  blindedCommitments[0].InitialOODQueries,
			OodAnswers: flattenOODAnswers(blindedCommitments[0].InitialOODAnswers),
		}
		blindingCommitmentNimue := ParsedCommitmentNimue{
			Root:       blindingCommitment.RootHash,
			OodPoints:  blindingCommitment.InitialOODQueries,
			OodAnswers: flattenOODAnswers(blindingCommitment.InitialOODAnswers),
		}

		mode := SingleCommitment
		if isDualMode {
			mode = DualCommitment1
		}

		err = ZKWhirVerify(
			api, sc, nimue,
			blindedCommitmentNimue,
			blindingCommitmentNimue,
			circuit.BlindedCommitmentWhirConfig,
			circuit.BlindingCommitmentWhirConfig,
			whirEvaluations,
			weightsLen,
			numPolynomials,
			&circuit.BlindedMerkleData,
			&circuit.BlindingMerkleData,
			R1CSWeightParams{
				Circuit:                circuit,
				Alpha:                  alpha,
				PublicWeightsChallenge: publicWeightsChallenge[0],
				HasPublicInputs:        hasPublicInputs,
				Mode:                   mode,
			},
		)
		if err != nil {
			return fmt.Errorf("ZK-WHIR verification failed for commitment 1: %w", err)
		}
	}

	// ---------------------------------------------------------------
	// 7. If dual mode: WHIR verification for commitment 2
	//    Commitment 2 has no public weight and no blinding weight → weightsLen=3
	// ---------------------------------------------------------------
	var azAtAlpha, bzAtAlpha, czAtAlpha frontend.Variable
	if isDualMode {
		if len(circuit.Evaluations2) < 3 {
			return fmt.Errorf("circuit.Evaluations2 must have at least 3 elements, got %d", len(circuit.Evaluations2))
		}
		evals2Az := circuit.Evaluations2[0]
		evals2Bz := circuit.Evaluations2[1]
		evals2Cz := circuit.Evaluations2[2]
		api.Println("evals2Az", evals2Az)
		api.Println("evals2Bz", evals2Bz)
		api.Println("evals2Cz", evals2Cz)

		whirEvaluations2 := []frontend.Variable{evals2Az, evals2Bz, evals2Cz}

		blindedCommitmentNimue2 := ParsedCommitmentNimue{
			Root:       blindedCommitments2[0].RootHash,
			OodPoints:  blindedCommitments2[0].InitialOODQueries,
			OodAnswers: flattenOODAnswers(blindedCommitments2[0].InitialOODAnswers),
		}
		blindingCommitmentNimue2 := ParsedCommitmentNimue{
			Root:       blindingCommitment2.RootHash,
			OodPoints:  blindingCommitment2.InitialOODQueries,
			OodAnswers: flattenOODAnswers(blindingCommitment2.InitialOODAnswers),
		}

		err = ZKWhirVerify(
			api, sc, nimue,
			blindedCommitmentNimue2,
			blindingCommitmentNimue2,
			circuit.BlindedCommitmentWhirConfig,
			circuit.BlindingCommitmentWhirConfig,
			whirEvaluations2,
			3, // weightsLen: 3 (A,B,C only, no public, no blinding)
			numPolynomials,
			&circuit.BlindedMerkleData2,
			&circuit.BlindingMerkleData2,
			R1CSWeightParams{
				Circuit:                circuit,
				Alpha:                  alpha,
				PublicWeightsChallenge: publicWeightsChallenge[0],
				HasPublicInputs:        false,
				Mode:                   DualCommitment2,
			},
		)
		if err != nil {
			return fmt.Errorf("ZK-WHIR verification failed for commitment 2: %w", err)
		}

		// az_at_alpha = evals_1 + evals_2 (Rust verifier sums the two)
		azAtAlpha = api.Add(evals1Az, evals2Az)
		bzAtAlpha = api.Add(evals1Bz, evals2Bz)
		czAtAlpha = api.Add(evals1Cz, evals2Cz)
	} else {
		azAtAlpha = evals1Az
		bzAtAlpha = evals1Bz
		czAtAlpha = evals1Cz
	}

	// ---------------------------------------------------------------
	// 8. Final R1CS constraint satisfaction check:
	//    f_at_alpha == (az·bz - cz) * eq(tRand, alpha)
	// ---------------------------------------------------------------
	eqRA := calculateEqCircuit(api, tRand, alpha)
	rhs := api.Mul(api.Sub(api.Mul(azAtAlpha, bzAtAlpha), czAtAlpha), eqRA)
	api.AssertIsEqual(fAtAlpha, rhs)

	return nil
}

// flattenOODAnswers converts [][]frontend.Variable (each inner slice is a
// single-element answer) into a flat []frontend.Variable.
func flattenOODAnswers(answers [][]frontend.Variable) []frontend.Variable {
	var flat []frontend.Variable
	for _, ans := range answers {
		flat = append(flat, ans...)
	}
	return flat
}

// configToNimueInit returns (circuit placeholder, assignment) for NimueInit.
// Circuit placeholder has all fields zeroed. Assignment is filled from cfg:
//   - ProtocolID[0]: little-endian field element from cfg.ProtocolID bytes 0..31
//   - ProtocolID[1]: little-endian field element from cfg.ProtocolID bytes 32..63
//   - SessionID:     little-endian field element from cfg.SessionID bytes 0..31
func configToNimueInit(cfg Config) (circuit, assign NimueInit) {
	var pid [64]byte
	copy(pid[:], cfg.ProtocolID)
	var sid [32]byte
	copy(sid[:], cfg.SessionID)

	assign = NimueInit{
		ProtocolID: [2]frontend.Variable{
			leBytesToNativeBigInt(pid[:32]),
			leBytesToNativeBigInt(pid[32:]),
		},
		SessionID: leBytesToNativeBigInt(sid[:]),
	}
	return circuit, assign
}

// DualCommitmentData holds the additional data needed for dual-commitment mode.
type DualCommitmentData struct {
	Evals2BigInt       []*big.Int
	BlindedMerkleData  whir.WhirMerkleData
	BlindingMerkleData whir.WhirMerkleData
}

// verifyCircuit builds the gnark circuit and runs Groth16 proving + verification.
func verifyCircuit(
	cfg Config,
	pk *groth16.ProvingKey,
	vk *groth16.VerifyingKey,
	internedR1CS R1CS,
	interner Interner,
	buildOps common.BuildOps,
	publicInputs PublicInputs,
	evaluationsBigInt []*big.Int, // [az, bz, cz] from prover hints (commitment 1)
	publicEvalBigInt *big.Int, // public input evaluation (nil if no public inputs)
	blindedMerkleData whir.WhirMerkleData,
	blindingMerkleData whir.WhirMerkleData,
	dualData *DualCommitmentData, // nil for single-commitment mode
) error {
	transcriptT := make([]uints.U8, len(cfg.NargString))
	contTranscript := make([]uints.U8, len(cfg.NargString))

	for i := range cfg.NargString {
		transcriptT[i] = uints.NewU8(cfg.NargString[i])
	}

	nimueInitCircuit, nimueInitAssign := configToNimueInit(cfg)

	matrixA, matrixB, matrixC, err := buildR1CSMatrixCells(internedR1CS, interner)
	if err != nil {
		return err
	}

	publicInputsContainer := PublicInputs{
		Values: make([]frontend.Variable, len(publicInputs.Values)),
	}

	// Circuit template: placeholder (zero-valued) fields for compilation.
	evalsContainer := make([]frontend.Variable, 3)
	blindedMerkleTemplate := allocateZeroWhirMerkleData(blindedMerkleData)
	blindingMerkleTemplate := allocateZeroWhirMerkleData(blindingMerkleData)

	// Dual-commitment templates
	var evals2Container []frontend.Variable
	var blindedMerkleTemplate2, blindingMerkleTemplate2 whir.WhirMerkleData
	if dualData != nil {
		evals2Container = make([]frontend.Variable, 3)
		blindedMerkleTemplate2 = allocateZeroWhirMerkleData(dualData.BlindedMerkleData)
		blindingMerkleTemplate2 = allocateZeroWhirMerkleData(dualData.BlindingMerkleData)
	}

	circuit := Circuit{
		InitializationData:           nimueInitCircuit,
		Transcript:                   contTranscript,
		LogNumConstraints:            cfg.LogNumConstraints,
		NumChallenges:                cfg.NumChallenges,
		W1Size:                       cfg.W1Size,
		BlindingCommitmentWhirConfig: NewWhirParams(cfg.BlindingCommitmentWhirConfig),
		BlindedCommitmentWhirConfig:  NewWhirParams(cfg.BlindedCommitmentWhirConfig),
		PublicInputs:                 publicInputsContainer,
		Evaluations:                  evalsContainer,
		Evaluations2:                 evals2Container,
		BlindedMerkleData:            blindedMerkleTemplate,
		BlindingMerkleData:           blindingMerkleTemplate,
		BlindedMerkleData2:           blindedMerkleTemplate2,
		BlindingMerkleData2:          blindingMerkleTemplate2,
		MatrixA:                      matrixA,
		MatrixB:                      matrixB,
		MatrixC:                      matrixC,
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("Failed to compile circuit: %v", err)
	}
	if buildOps.OutputCcsPath != "" {
		ccsFile, err := os.Create(buildOps.OutputCcsPath)
		if err != nil {
			log.Printf("Cannot create ccs file %s: %v", buildOps.OutputCcsPath, err)
		} else {
			_, err = ccs.WriteTo(ccsFile)
			if err != nil {
				log.Printf("Cannot write ccs file %s: %v", buildOps.OutputCcsPath, err)
			}
		}
		log.Printf("ccs written to %s", buildOps.OutputCcsPath)
	}

	if pk == nil || vk == nil {
		log.Printf("PK/VK not provided, generating new keys unsafely. Consider providing keys from an MPC ceremony.")
		unsafePk, unsafeVk, err := groth16.Setup(ccs)
		if err != nil {
			log.Fatalf("Failed to setup groth16: %v", err)
		}
		pk = &unsafePk
		vk = &unsafeVk

		if buildOps.ShouldSaveKeys() {
			if err := os.MkdirAll(buildOps.SaveKeys, 0o755); err != nil {
				log.Printf("Failed to create save keys directory %s: %v", buildOps.SaveKeys, err)
			}

			timestamp := time.Now().Format("02Jan_15-04-05")

			pkFilename := filepath.Join(buildOps.SaveKeys, fmt.Sprintf("pk_%s.bin", timestamp))
			pkFile, err := os.Create(pkFilename)
			if err != nil {
				log.Printf("Failed to create PK file: %v", err)
			} else {
				defer func() {
					if err := pkFile.Close(); err != nil {
						log.Printf("Failed to close PK file: %v", err)
					}
				}()
				if _, err = (*pk).WriteTo(pkFile); err != nil {
					log.Printf("Failed to write PK to file: %v", err)
				} else {
					log.Printf("Proving key saved to %s", pkFilename)
				}
			}

			vkFilename := filepath.Join(buildOps.SaveKeys, fmt.Sprintf("vk_%s.bin", timestamp))
			vkFile, err := os.Create(vkFilename)
			if err != nil {
				log.Printf("Failed to create VK file: %v", err)
			} else {
				defer func() {
					if err := vkFile.Close(); err != nil {
						log.Printf("Failed to close VK file: %v", err)
					}
				}()
				if _, err = (*vk).WriteTo(vkFile); err != nil {
					log.Printf("Failed to write VK to file: %v", err)
				} else {
					log.Printf("Verifying key saved to %s", vkFilename)
				}
			}
		}
	}

	// Build evaluation witness values from the native-parsed big.Ints.
	evalsAssign := make([]frontend.Variable, 3)
	for i := 0; i < 3 && i < len(evaluationsBigInt); i++ {
		evalsAssign[i] = evaluationsBigInt[i]
	}
	var publicEvalAssign frontend.Variable
	if publicEvalBigInt != nil {
		publicEvalAssign = publicEvalBigInt
	} else {
		publicEvalAssign = big.NewInt(0)
	}

	// Build dual-commitment assignment data
	var evals2Assign []frontend.Variable
	var blindedMerkleAssign2, blindingMerkleAssign2 whir.WhirMerkleData
	if dualData != nil {
		evals2Assign = make([]frontend.Variable, 3)
		for i := 0; i < 3 && i < len(dualData.Evals2BigInt); i++ {
			evals2Assign[i] = dualData.Evals2BigInt[i]
		}
		blindedMerkleAssign2 = dualData.BlindedMerkleData
		blindingMerkleAssign2 = dualData.BlindingMerkleData
	}

	assignment := Circuit{
		InitializationData:           nimueInitAssign,
		Transcript:                   transcriptT,
		LogNumConstraints:            cfg.LogNumConstraints,
		NumChallenges:                cfg.NumChallenges,
		W1Size:                       cfg.W1Size,
		BlindingCommitmentWhirConfig: NewWhirParams(cfg.BlindingCommitmentWhirConfig),
		BlindedCommitmentWhirConfig:  NewWhirParams(cfg.BlindedCommitmentWhirConfig),
		PublicInputs:                 publicInputs,
		Evaluations:                  evalsAssign,
		Evaluations2:                 evals2Assign,
		PublicEval:                   publicEvalAssign,
		BlindedMerkleData:            blindedMerkleData,
		BlindingMerkleData:           blindingMerkleData,
		BlindedMerkleData2:           blindedMerkleAssign2,
		BlindingMerkleData2:          blindingMerkleAssign2,
		MatrixA:                      matrixA,
		MatrixB:                      matrixB,
		MatrixC:                      matrixC,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		log.Printf("Failed to create witness: %v", err)
		return err
	}
	publicWitness, err := witness.Public()
	if err != nil {
		log.Printf("Failed witness, Public(): %v", err)
		return err
	}

	opts := []backend.ProverOption{
		backend.WithSolverOptions(solver.WithHints(utilities.IndexOf)),
		backend.WithIcicleAcceleration(),
	}

	proof, err := groth16.Prove(ccs, *pk, witness, opts...)
	if err != nil {
		log.Printf("Failed to prove: %v", err)
		return err
	}
	err = groth16.Verify(proof, *vk, publicWitness)
	if err != nil {
		log.Printf("Failed to verify proof: %v", err)
		return err
	}
	return nil
}

// allocateZeroWhirMerkleData creates a zero-valued copy of a WhirMerkleData
// with the same shape. Used as the circuit template for gnark compilation;
// the actual values go in the assignment only.
func allocateZeroWhirMerkleData(src whir.WhirMerkleData) whir.WhirMerkleData {
	dst := whir.WhirMerkleData{
		Rounds: make([]whir.RoundMerkleEntry, len(src.Rounds)),
	}
	for r, rd := range src.Rounds {
		nq := len(rd.Leaves)
		entry := whir.RoundMerkleEntry{
			Leaves:        make([][]frontend.Variable, nq),
			SiblingHashes: make([]frontend.Variable, nq),
			AuthPaths:     make([][]frontend.Variable, nq),
			LeafIndexes:   make([]frontend.Variable, nq),
		}
		for q := range nq {
			if len(rd.Leaves[q]) > 0 {
				entry.Leaves[q] = make([]frontend.Variable, len(rd.Leaves[q]))
			}
			if len(rd.AuthPaths[q]) > 0 {
				entry.AuthPaths[q] = make([]frontend.Variable, len(rd.AuthPaths[q]))
			}
		}
		dst.Rounds[r] = entry
	}
	return dst
}
