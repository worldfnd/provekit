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
	// ProtocolID is SHA3-512(CBOR(WhirR1CSScheme)) for this circuit shape.
	// SessionIDBytes is the raw 32-byte session id used in domain separation.
	// Both are fixed for a given circuit instance, so we carry them as
	// Go-typed fields (not frontend.Variable) so gnark inlines them as
	// constants in the constraint system rather than allocating witness
	// variables.
	ProtocolID        [64]byte
	SessionIDBytes    [32]byte
	LogNumConstraints int

	SessionID                    [32]uints.U8 `gnark:",public"`
	Transcript                   []uints.U8   `gnark:",public"`
	BlindingCommitmentWhirConfig WHIRParams
	BlindedCommitmentWhirConfig  WHIRParams
	NumChallenges                int
	ChallengeOffsets             []int
	W1Size                       int
	PublicInputs                 PublicInputs

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

	blindedCommitments, blindingCommitment, err := zkWHIRCommitmentParsing(api, nimue, circuit.BlindedCommitmentWhirConfig, circuit.BlindingCommitmentWhirConfig, 1)
	// api.Println("blindedCommitments", blindedCommitments)
	// api.Println("blindingCommitment", blindingCommitment)
	if err != nil {
		return err
	}
	numPolynomials := 1
	isDualMode := circuit.NumChallenges > 0

	var blindedCommitments2 []Commitment
	var blindingCommitment2 Commitment
	if isDualMode {
		logupChallenges := make([]frontend.Variable, circuit.NumChallenges)
		if err = nimue.FillChallengeScalars(logupChallenges); err != nil {
			return err
		}

		blindedCommitments2, blindingCommitment2, err = zkWHIRCommitmentParsing(api, nimue, circuit.BlindedCommitmentWhirConfig, circuit.BlindingCommitmentWhirConfig, 1)
		// api.Println("blindedCommitments2", blindedCommitments2)
		// api.Println("blindingCommitment2", blindingCommitment2)
		if err != nil {
			return err
		}
	}

	tRand, alpha, fAtAlpha, blindingEval, err := runZKSumcheck(api, sc, uapi, circuit, nimue, frontend.Variable(0), circuit.LogNumConstraints, 4)
	if err != nil {
		return err
	}

	// Public inputs hash check + x challenge
	err = publicInputsHashCheck(api, sc, nimue, circuit.PublicInputs)
	if err != nil {
		return err
	}

	publicWeightsChallenge := make([]frontend.Variable, 1)
	if err := nimue.FillChallengeScalars(publicWeightsChallenge); err != nil {
		return fmt.Errorf("failed to read public weights challenge: %w", err)
	}

	// Read evaluations from transcript (prover_message in Rust)
	evals1 := make([]frontend.Variable, 3)
	if err := nimue.FillNextScalars(evals1); err != nil {
		return fmt.Errorf("failed to read evals_1 from transcript: %w", err)
	}
	evals1Az := evals1[0]
	evals1Bz := evals1[1]
	evals1Cz := evals1[2]

	// In dual mode, evals_2 follows evals_1 in the transcript (before public_eval).
	var evals2Az, evals2Bz, evals2Cz frontend.Variable
	if isDualMode {
		evals2 := make([]frontend.Variable, 3)
		if err := nimue.FillNextScalars(evals2); err != nil {
			return fmt.Errorf("failed to read evals_2 from transcript: %w", err)
		}
		evals2Az = evals2[0]
		evals2Bz = evals2[1]
		evals2Cz = evals2[2]
	}

	hasPublicInputs := !circuit.PublicInputs.IsEmpty()

	var publicEval frontend.Variable
	if hasPublicInputs {
		publicEvalSlice := make([]frontend.Variable, 1)
		if err := nimue.FillNextScalars(publicEvalSlice); err != nil {
			return fmt.Errorf("failed to read public_eval from transcript: %w", err)
		}
		publicEval = publicEvalSlice[0]

		// Verify public input binding (Rust: verify_public_input_binding).
		// expected = 1 + x*pi[0] + x²*pi[1] + ...
		// where x = publicWeightsChallenge and position 0 is the constant 1.
		expectedPublicEval := frontend.Variable(1)
		xPow := publicWeightsChallenge[0]
		for _, pi := range circuit.PublicInputs.Values {
			expectedPublicEval = api.Add(expectedPublicEval, api.Mul(xPow, pi))
			xPow = api.Mul(xPow, publicWeightsChallenge[0])
		}
		api.AssertIsEqual(publicEval, expectedPublicEval)
	}

	// Challenge binding: in dual mode, read challenge_eval from transcript.
	var challengeEval frontend.Variable
	if isDualMode {
		ceSlice := make([]frontend.Variable, 1)
		if err := nimue.FillNextScalars(ceSlice); err != nil {
			return fmt.Errorf("failed to read challenge_eval from transcript: %w", err)
		}
		challengeEval = ceSlice[0]
	}

	var whirEvaluations []frontend.Variable
	if hasPublicInputs {
		whirEvaluations = []frontend.Variable{publicEval, evals1Az, evals1Bz, evals1Cz, blindingEval}
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

	var azAtAlpha, bzAtAlpha, czAtAlpha frontend.Variable
	if isDualMode {
		// Commitment 2 has 3 base weights (A,B,C) + 1 challenge weight if challenge_eval exists.
		whirEvaluations2 := []frontend.Variable{evals2Az, evals2Bz, evals2Cz}
		weightsLen2 := 3
		if circuit.NumChallenges > 0 {
			whirEvaluations2 = append(whirEvaluations2, challengeEval)
			weightsLen2 = 4
		}

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
			weightsLen2,
			numPolynomials,
			&circuit.BlindedMerkleData2,
			&circuit.BlindingMerkleData2,
			R1CSWeightParams{
				Circuit:                circuit,
				Alpha:                  alpha,
				PublicWeightsChallenge: publicWeightsChallenge[0],
				HasPublicInputs:        false,
				ChallengeOffsets:       circuit.ChallengeOffsets,
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

	eqRA := calculateEqCircuit(api, tRand, alpha)
	rhs := api.Mul(api.Sub(api.Mul(azAtAlpha, bzAtAlpha), czAtAlpha), eqRA)
	api.AssertIsEqual(fAtAlpha, rhs)

	if remaining := nimue.RemainingTranscriptLen(); remaining != 0 {
		return fmt.Errorf("transcript not fully consumed: %d bytes remaining", remaining)
	}

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
	blindedMerkleData whir.WhirMerkleData,
	blindingMerkleData whir.WhirMerkleData,
	dualData *DualCommitmentData, // nil for single-commitment mode
) error {
	transcriptT := make([]uints.U8, len(cfg.NargString))
	contTranscript := make([]uints.U8, len(cfg.NargString))

	for i := range cfg.NargString {
		transcriptT[i] = uints.NewU8(cfg.NargString[i])
	}

	var protocolID [64]byte
	copy(protocolID[:], cfg.ProtocolID)
	var sessionIDBytes [32]byte
	copy(sessionIDBytes[:], cfg.SessionID)

	matrixA, matrixB, matrixC, err := buildR1CSMatrixCells(internedR1CS, interner)
	if err != nil {
		return err
	}

	publicInputsContainer := PublicInputs{
		Values: make([]frontend.Variable, len(publicInputs.Values)),
	}

	// Circuit template: placeholder (zero-valued) fields for compilation.
	blindedMerkleTemplate := allocateZeroWhirMerkleData(blindedMerkleData)
	blindingMerkleTemplate := allocateZeroWhirMerkleData(blindingMerkleData)

	// Dual-commitment templates
	var blindedMerkleTemplate2, blindingMerkleTemplate2 whir.WhirMerkleData
	if dualData != nil {
		blindedMerkleTemplate2 = allocateZeroWhirMerkleData(dualData.BlindedMerkleData)
		blindingMerkleTemplate2 = allocateZeroWhirMerkleData(dualData.BlindingMerkleData)
	}

	circuit := Circuit{
		ProtocolID:                   protocolID,
		SessionIDBytes:               sessionIDBytes,
		Transcript:                   contTranscript,
		LogNumConstraints:            cfg.LogNumConstraints,
		NumChallenges:                cfg.NumChallenges,
		ChallengeOffsets:             cfg.ChallengeOffsets,
		W1Size:                       cfg.W1Size,
		BlindingCommitmentWhirConfig: NewWhirParams(cfg.BlindingCommitmentWhirConfig),
		BlindedCommitmentWhirConfig:  NewWhirParams(cfg.BlindedCommitmentWhirConfig),
		PublicInputs:                 publicInputsContainer,
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

	// Build dual-commitment assignment data
	var blindedMerkleAssign2, blindingMerkleAssign2 whir.WhirMerkleData
	if dualData != nil {
		blindedMerkleAssign2 = dualData.BlindedMerkleData
		blindingMerkleAssign2 = dualData.BlindingMerkleData
	}

	assignment := Circuit{
		ProtocolID:                   protocolID,
		SessionIDBytes:               sessionIDBytes,
		Transcript:                   transcriptT,
		LogNumConstraints:            cfg.LogNumConstraints,
		NumChallenges:                cfg.NumChallenges,
		ChallengeOffsets:             cfg.ChallengeOffsets,
		W1Size:                       cfg.W1Size,
		BlindingCommitmentWhirConfig: NewWhirParams(cfg.BlindingCommitmentWhirConfig),
		BlindedCommitmentWhirConfig:  NewWhirParams(cfg.BlindedCommitmentWhirConfig),
		PublicInputs:                 publicInputs,
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
