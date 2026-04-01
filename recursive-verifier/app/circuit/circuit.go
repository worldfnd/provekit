package circuit

import (
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"reilabs/whir-verifier-circuit/app/common"
	"reilabs/whir-verifier-circuit/app/typeConverters"
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
	// Single commitment: [az_at_alpha, bz_at_alpha, cz_at_alpha]
	Evaluations []frontend.Variable
	// Public input evaluation hint (only used when PublicInputs is non-empty).
	PublicEval frontend.Variable

	// Merkle proof data for WHIR commitment verification.
	BlindedMerkleData  whir.WhirMerkleData
	BlindingMerkleData whir.WhirMerkleData

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
	api.Println("blindedCommitments", blindedCommitments)
	api.Println("blindingCommitment", blindingCommitment)
	if err != nil {
		return err
	}
	numPolynomials := 1

	if circuit.NumChallenges > 0 {
		// Squeeze logup challenges
		logupChallenges := make([]frontend.Variable, circuit.NumChallenges)
		if err = nimue.FillChallengeScalars(logupChallenges); err != nil {
			return err
		}

		// Parse second commitment (C2)
		blindedCommitments2, blindingCommitment2, err := zkWHIRCommitmentParsing(api, nimue, circuit.BlindedCommitmentWhirConfig, circuit.BlindingCommitmentWhirConfig, 1)
		api.Println("blindedCommitments2", blindedCommitments2)
		api.Println("blindingCommitment2", blindingCommitment2)
		if err != nil {
			return err
		}
	}

	// Run ZK sumcheck — returns tRand (r), alpha (folding challenges), and blindingEval.
	tRand, alpha, fAtAlpha, blindingEval, err := runZKSumcheck(api, sc, uapi, circuit, nimue, frontend.Variable(0), circuit.LogNumConstraints, 4)
	if err != nil {
		return err
	}
	api.Println("tRand", tRand)
	api.Println("alpha", alpha)
	api.Println("fAtAlpha", fAtAlpha)
	api.Println("blindingEval", blindingEval)

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
	// Single commitment WHIR R1CS verification
	// (mirrors Rust verifier lines 172-214, single commitment path)
	// ---------------------------------------------------------------

	// Evaluation hints (az_at_alpha, bz_at_alpha, cz_at_alpha) come from
	// prover_hint_ark in the Rust verifier (hint stream, not transcript).
	// They are passed as circuit witness fields.
	if len(circuit.Evaluations) < 3 {
		return fmt.Errorf("circuit.Evaluations must have at least 3 elements, got %d", len(circuit.Evaluations))
	}
	azAtAlpha := circuit.Evaluations[0]
	bzAtAlpha := circuit.Evaluations[1]
	czAtAlpha := circuit.Evaluations[2]
	api.Println("azAtAlpha", azAtAlpha)
	api.Println("bzAtAlpha", bzAtAlpha)
	api.Println("czAtAlpha", czAtAlpha)

	// Build the evaluations list for WHIR verify.
	// Includes blinding_eval as the last weight, matching Rust's
	// [pub?, az, bz, cz, blinding_eval] passed to whir_zk::verify.
	hasPublicInputs := !circuit.PublicInputs.IsEmpty()
	var whirEvaluations []frontend.Variable

	if hasPublicInputs {
		api.Println("publicEval", circuit.PublicEval)
		whirEvaluations = []frontend.Variable{circuit.PublicEval, azAtAlpha, bzAtAlpha, czAtAlpha, blindingEval}
	} else {
		whirEvaluations = []frontend.Variable{azAtAlpha, bzAtAlpha, czAtAlpha, blindingEval}
	}

	// Determine weights length: 3 (A,B,C) + optional public + blinding = 4 or 5
	// weightsLen includes the blinding weight for computing numWFoldedEvals
	// in the ZK wrapper, even though evaluations doesn't include blinding_eval.
	weightsLen := 4
	if hasPublicInputs {
		weightsLen = 5
	}

	// Convert parsed commitments to nimue format
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

	// Run ZK-WHIR verification (single commitment version)
	err = ZKWhirVerifyNimue(
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
		},
	)
	if err != nil {
		return fmt.Errorf("ZK-WHIR verification failed: %w", err)
	}

	// ---------------------------------------------------------------
	// Final R1CS constraint satisfaction check:
	// f_at_alpha == (az·bz - cz) * eq(tRand, alpha)
	//
	// tRand is the Spartan verifier randomness (r), alpha is the
	// sumcheck folding challenges, fAtAlpha is the unblinded last
	// evaluation from the sumcheck.
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

// verifyCircuit builds the gnark circuit and runs Groth16 proving + verification.
// Currently stubbed: the circuit requires transcript/IOPattern fields that are
// being replaced by native spongefish replay. Will be re-enabled once the
// SpongefishArthur-based circuit is integrated.
//
//nolint:unused
func verifyCircuit(
	cfg Config,
	pk *groth16.ProvingKey,
	vk *groth16.VerifyingKey,
	internedR1CS R1CS,
	interner Interner,
	buildOps common.BuildOps,
	publicInputs PublicInputs,
	evaluationsBigInt []*big.Int, // [az, bz, cz] from prover hints
	publicEvalBigInt *big.Int, // public input evaluation (nil if no public inputs)
	blindedMerkleData whir.WhirMerkleData,
	blindingMerkleData whir.WhirMerkleData,
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
		BlindedMerkleData:            blindedMerkleTemplate,
		BlindingMerkleData:           blindingMerkleTemplate,
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
			// Create the save keys directory if it doesn't exist
			if err := os.MkdirAll(buildOps.SaveKeys, 0o755); err != nil {
				log.Printf("Failed to create save keys directory %s: %v", buildOps.SaveKeys, err)
			}

			// Generate timestamp for filenames
			timestamp := time.Now().Format("02Jan_15-04-05")

			// Save proving key to file
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
				_, err = (*pk).WriteTo(pkFile) // Dereference with (*pk)
				if err != nil {
					log.Printf("Failed to write PK to file: %v", err)
				} else {
					log.Printf("Proving key saved to %s", pkFilename)
				}
			}

			// Save verifying key to file
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
				_, err = (*vk).WriteTo(vkFile) // Dereference with (*vk)
				if err != nil {
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
		PublicEval:                   publicEvalAssign,
		BlindedMerkleData:            blindedMerkleData,
		BlindingMerkleData:           blindingMerkleData,
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

//nolint:unused
func parseClaimedEvaluations(claimedEvaluations ClaimedEvaluations, isContainer bool) ([]frontend.Variable, []frontend.Variable) {
	fSums := make([]frontend.Variable, len(claimedEvaluations.FSums))
	gSums := make([]frontend.Variable, len(claimedEvaluations.GSums))

	if !isContainer {
		for i := range claimedEvaluations.FSums {
			fSums[i] = typeConverters.LimbsToBigIntMod(claimedEvaluations.FSums[i].Limbs)
			gSums[i] = typeConverters.LimbsToBigIntMod(claimedEvaluations.GSums[i].Limbs)
		}
	}

	return fSums, gSums
}

//nolint:unused
func witnessFirstRounds(hints Hints, isContainer bool) []Merkle {
	result := make([]Merkle, len(hints.WitnessFirstRoundHints))
	for i, hint := range hints.WitnessFirstRoundHints {
		result[i] = newMerkle(hint.path, isContainer)
	}
	return result
}

//nolint:unused
func parsePublicWeightsClaimedEvaluation(publicWeightsClaimedEvaluation [2]Fp256, isContainer bool) (frontend.Variable, frontend.Variable) {
	var fSumPublicWeights, gSumPublicWeights frontend.Variable

	if !isContainer {
		fSumPublicWeights = typeConverters.LimbsToBigIntMod(publicWeightsClaimedEvaluation[0].Limbs)
		gSumPublicWeights = typeConverters.LimbsToBigIntMod(publicWeightsClaimedEvaluation[1].Limbs)
	}

	return fSumPublicWeights, gSumPublicWeights
}

func extendLinearStatement(
	circuit *Circuit,
	linearStatementEvaluations [][]frontend.Variable,
	pubWitnessEvaluations []frontend.Variable,
) [][]frontend.Variable {
	var extendedLinearStatementEvals [][]frontend.Variable

	if !circuit.PublicInputs.IsEmpty() {
		// Extend the statement equivalent array by prepending the public constraint (public constraint is added in starting at prover side)
		extendedLinearStatementEvals = make([][]frontend.Variable, 2)

		// f_sums: [public_f_sum, f_sums[0], f_sums[1]... ]
		extendedLinearStatementEvals[0] = make([]frontend.Variable, len(linearStatementEvaluations[0])+1)
		extendedLinearStatementEvals[0][0] = pubWitnessEvaluations[0]
		copy(extendedLinearStatementEvals[0][1:], linearStatementEvaluations[0])

		// g_sums: [public_g_sum, g_sums[0], g_sums[1]... ]
		extendedLinearStatementEvals[1] = make([]frontend.Variable, len(linearStatementEvaluations[1])+1)
		extendedLinearStatementEvals[1][0] = pubWitnessEvaluations[1]
		copy(extendedLinearStatementEvals[1][1:], linearStatementEvaluations[1])
	} else {
		// No public inputs, use original arrays
		extendedLinearStatementEvals = linearStatementEvaluations
	}

	return extendedLinearStatementEvals
}
