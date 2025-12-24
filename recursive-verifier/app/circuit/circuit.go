package circuit

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"reilabs/whir-verifier-circuit/app/common"
	"reilabs/whir-verifier-circuit/app/typeConverters"
	"reilabs/whir-verifier-circuit/app/utilities"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
)

type Circuit struct {
	// Inputs
	WitnessLinearStatementEvaluations       []frontend.Variable
	HidingSpartanLinearStatementEvaluations []frontend.Variable
	LogNumConstraints                       int
	LogNumVariables                         int
	LogANumTerms                            int
	HidingSpartanFirstRound                 Merkle
	HidingSpartanMerkle                     Merkle
	WHIRParamsWitness                       WHIRParams
	WHIRParamsHidingSpartan                 WHIRParams
	NumChallenges                           int
	W1Size                                  int

	// Witness commitments (length 1 for single mode, N for batch mode)
	WitnessFirstRounds         []Merkle
	WitnessClaimedEvaluations  [][]frontend.Variable // [commitment_idx][eval_idx]
	WitnessBlindingEvaluations [][]frontend.Variable

	// Batch mode only: batched polynomial for rounds 1+
	WitnessMerkle Merkle

	MatrixA []MatrixCell
	MatrixB []MatrixCell
	MatrixC []MatrixCell

	// Public Input
	IO         []byte
	Transcript []uints.U8 `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	sc, arthur, uapi, err := initializeComponents(api, circuit)
	if err != nil {
		return err
	}

	// Parse first commitment (C1) - needed to consume transcript
	rootHash1, batchingRandomness1, initialOODQueries1, initialOODAnswers1, err := parseBatchedCommitment(arthur, circuit.WHIRParamsWitness)
	if err != nil {
		return err
	}

	// Variables for second commitment (only used in dual mode)
	var rootHash2, batchingRandomness2 frontend.Variable
	var initialOODQueries2 []frontend.Variable
	var initialOODAnswers2 [][]frontend.Variable

	if circuit.NumChallenges > 0 {
		// Squeeze logup challenges
		logupChallenges := make([]frontend.Variable, circuit.NumChallenges)
		if err = arthur.FillChallengeScalars(logupChallenges); err != nil {
			return err
		}

		// Parse second commitment (C2)
		rootHash2, batchingRandomness2, initialOODQueries2, initialOODAnswers2, err = parseBatchedCommitment(arthur, circuit.WHIRParamsWitness)
		if err != nil {
			return err
		}
	}

	// Squeeze tRand for Spartan
	tRand := make([]frontend.Variable, circuit.LogNumConstraints)
	err = arthur.FillChallengeScalars(tRand)
	if err != nil {
		return err
	}

	// Run ZK sumcheck
	spartanSumcheckRand, spartanSumcheckLastValue, err := runZKSumcheck(api, sc, uapi, circuit, arthur, frontend.Variable(0), circuit.LogNumConstraints, 4, circuit.WHIRParamsHidingSpartan)
	if err != nil {
		return err
	}

	// WHIR verification
	var whirFoldingRandomness []frontend.Variable
	var az, bz, cz frontend.Variable

	if circuit.NumChallenges > 0 {
		// Dual commitment mode: batch WHIR verification
		whirFoldingRandomness, err = RunZKWhirBatch(
			api, arthur, uapi, sc,
			circuit.WitnessFirstRounds,                                      // firstRounds []Merkle
			[]frontend.Variable{batchingRandomness1, batchingRandomness2},   // batchingRandomnesses
			[][]frontend.Variable{initialOODQueries1, initialOODQueries2},   // initialOODQueries
			[][][]frontend.Variable{initialOODAnswers1, initialOODAnswers2}, // initialOODAnswers
			[]frontend.Variable{rootHash1, rootHash2},                       // rootHashes
			circuit.WitnessMerkle,                                           // batchedMerkle
			[][][]frontend.Variable{ // linearStatementEvals
				{circuit.WitnessClaimedEvaluations[0], circuit.WitnessBlindingEvaluations[0]},
				{circuit.WitnessClaimedEvaluations[1], circuit.WitnessBlindingEvaluations[1]},
			},
			circuit.WHIRParamsWitness,                 // whirParams
			circuit.WitnessLinearStatementEvaluations, // linearStatementValuesAtPoints
		)
		if err != nil {
			return err
		}

		// Sum evaluations from both commitments
		az = api.Add(circuit.WitnessClaimedEvaluations[0][0], circuit.WitnessClaimedEvaluations[1][0])
		bz = api.Add(circuit.WitnessClaimedEvaluations[0][1], circuit.WitnessClaimedEvaluations[1][1])
		cz = api.Add(circuit.WitnessClaimedEvaluations[0][2], circuit.WitnessClaimedEvaluations[1][2])
	} else {
		// Single commitment mode
		whirFoldingRandomness, err = RunZKWhir(
			api, arthur, uapi, sc,
			circuit.WitnessMerkle, circuit.WitnessFirstRounds[0],
			circuit.WHIRParamsWitness,
			[][]frontend.Variable{circuit.WitnessClaimedEvaluations[0], circuit.WitnessBlindingEvaluations[0]},
			circuit.WitnessLinearStatementEvaluations,
			batchingRandomness1,
			initialOODQueries1,
			initialOODAnswers1,
			rootHash1,
		)
		if err != nil {
			return err
		}

		az = circuit.WitnessClaimedEvaluations[0][0]
		bz = circuit.WitnessClaimedEvaluations[0][1]
		cz = circuit.WitnessClaimedEvaluations[0][2]
	}

	// Spartan sumcheck relation check (common to both modes)
	x := api.Mul(api.Sub(api.Mul(az, bz), cz), calculateEQ(api, spartanSumcheckRand, tRand))
	api.AssertIsEqual(spartanSumcheckLastValue, x)

	if circuit.NumChallenges > 0 {
		// Batch mode - check 6 deferred values
		matrixExtensionEvals := evaluateR1CSMatrixExtensionBatch(api, circuit, spartanSumcheckRand, whirFoldingRandomness, circuit.W1Size)
		for i := 0; i < 6; i++ {
			api.AssertIsEqual(matrixExtensionEvals[i], circuit.WitnessLinearStatementEvaluations[i])
		}
	} else {
		// Single mode - existing logic
		matrixExtensionEvals := evaluateR1CSMatrixExtension(api, circuit, spartanSumcheckRand, whirFoldingRandomness)
		for i := 0; i < 3; i++ {
			api.AssertIsEqual(matrixExtensionEvals[i], circuit.WitnessLinearStatementEvaluations[i])
		}
	}

	return nil
}

func verifyCircuit(
	deferred []Fp256,
	cfg Config,
	hints Hints,
	pk *groth16.ProvingKey,
	vk *groth16.VerifyingKey,
	claimedEvaluations ClaimedEvaluations,
	claimedEvaluations2 ClaimedEvaluations,
	internedR1CS R1CS,
	interner Interner,
	buildOps common.BuildOps,
) error {
	transcriptT := make([]uints.U8, cfg.TranscriptLen)
	contTranscript := make([]uints.U8, cfg.TranscriptLen)

	for i := range cfg.Transcript {
		transcriptT[i] = uints.NewU8(cfg.Transcript[i])
	}

	// Determine witness linear statement evals size based on mode
	var witnessLinearStatementEvalsSize int
	if cfg.NumChallenges > 0 {
		witnessLinearStatementEvalsSize = 6 // 3 per commitment in batch mode
	} else {
		witnessLinearStatementEvalsSize = 3
	}

	witnessLinearStatementEvaluations := make([]frontend.Variable, witnessLinearStatementEvalsSize)
	hidingSpartanLinearStatementEvaluations := make([]frontend.Variable, 1)
	contWitnessLinearStatementEvaluations := make([]frontend.Variable, witnessLinearStatementEvalsSize)
	contHidingSpartanLinearStatementEvaluations := make([]frontend.Variable, 1)

	hidingSpartanLinearStatementEvaluations[0] = typeConverters.LimbsToBigIntMod(deferred[0].Limbs)
	for i := 0; i < witnessLinearStatementEvalsSize; i++ {
		witnessLinearStatementEvaluations[i] = typeConverters.LimbsToBigIntMod(deferred[1+i].Limbs)
	}

	matrixA := make([]MatrixCell, len(internedR1CS.A.Values))
	for i := range len(internedR1CS.A.RowIndices) {
		end := len(internedR1CS.A.Values) - 1
		if i < len(internedR1CS.A.RowIndices)-1 {
			end = int(internedR1CS.A.RowIndices[i+1] - 1)
		}
		for j := int(internedR1CS.A.RowIndices[i]); j <= end; j++ {
			matrixA[j] = MatrixCell{
				row:    i,
				column: int(internedR1CS.A.ColIndices[j]),
				value:  typeConverters.LimbsToBigIntMod(interner.Values[internedR1CS.A.Values[j]].Limbs),
			}
		}
	}

	matrixB := make([]MatrixCell, len(internedR1CS.B.Values))
	for i := range len(internedR1CS.B.RowIndices) {
		end := len(internedR1CS.B.Values) - 1
		if i < len(internedR1CS.B.RowIndices)-1 {
			end = int(internedR1CS.B.RowIndices[i+1] - 1)
		}
		for j := int(internedR1CS.B.RowIndices[i]); j <= end; j++ {
			matrixB[j] = MatrixCell{
				row:    i,
				column: int(internedR1CS.B.ColIndices[j]),
				value:  typeConverters.LimbsToBigIntMod(interner.Values[internedR1CS.B.Values[j]].Limbs),
			}
		}
	}

	matrixC := make([]MatrixCell, len(internedR1CS.C.Values))
	for i := range len(internedR1CS.C.RowIndices) {
		end := len(internedR1CS.C.Values) - 1
		if i < len(internedR1CS.C.RowIndices)-1 {
			end = int(internedR1CS.C.RowIndices[i+1] - 1)
		}
		for j := int(internedR1CS.C.RowIndices[i]); j <= end; j++ {
			matrixC[j] = MatrixCell{
				row:    i,
				column: int(internedR1CS.C.ColIndices[j]),
				value:  typeConverters.LimbsToBigIntMod(interner.Values[internedR1CS.C.Values[j]].Limbs),
			}
		}
	}

	// Parse claimed evaluations for first commitment
	fSums, gSums := parseClaimedEvaluations(claimedEvaluations, true)

	// Parse claimed evaluations for second commitment (if dual mode)
	var fSums2, gSums2 []frontend.Variable
	if cfg.NumChallenges > 0 {
		fSums2, gSums2 = parseClaimedEvaluations(claimedEvaluations2, true)
	}

	// Build witness slices conditionally
	var witnessClaimedEvals, witnessBlindingEvals [][]frontend.Variable
	if cfg.NumChallenges > 0 {
		witnessClaimedEvals = [][]frontend.Variable{fSums, fSums2}
		witnessBlindingEvals = [][]frontend.Variable{gSums, gSums2}
	} else {
		witnessClaimedEvals = [][]frontend.Variable{fSums}
		witnessBlindingEvals = [][]frontend.Variable{gSums}
	}

	circuit := Circuit{
		IO:                                      []byte(cfg.IOPattern),
		Transcript:                              contTranscript,
		LogNumConstraints:                       cfg.LogNumConstraints,
		LogNumVariables:                         cfg.LogNumVariables,
		LogANumTerms:                            cfg.LogANumTerms,
		WitnessClaimedEvaluations:               witnessClaimedEvals,
		WitnessBlindingEvaluations:              witnessBlindingEvals,
		WitnessLinearStatementEvaluations:       contWitnessLinearStatementEvaluations,
		HidingSpartanLinearStatementEvaluations: contHidingSpartanLinearStatementEvaluations,
		HidingSpartanFirstRound:                 newMerkle(hints.spartanHidingHint.firstRoundMerklePaths.path, true),
		HidingSpartanMerkle:                     newMerkle(hints.spartanHidingHint.roundHints, true),
		WitnessFirstRounds:                      witnessFirstRounds(hints, true),
		WitnessMerkle:                           newMerkle(hints.WitnessRoundHints.roundHints, true),
		NumChallenges:                           cfg.NumChallenges,
		W1Size:                                  cfg.W1Size,
		WHIRParamsWitness:                       NewWhirParams(cfg.WHIRConfigWitness),
		WHIRParamsHidingSpartan:                 NewWhirParams(cfg.WHIRConfigHidingSpartan),
		MatrixA:                                 matrixA,
		MatrixB:                                 matrixB,
		MatrixC:                                 matrixC,
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

	// Parse actual values for assignment
	fSums, gSums = parseClaimedEvaluations(claimedEvaluations, false)
	if cfg.NumChallenges > 0 {
		fSums2, gSums2 = parseClaimedEvaluations(claimedEvaluations2, false)
		witnessClaimedEvals = [][]frontend.Variable{fSums, fSums2}
		witnessBlindingEvals = [][]frontend.Variable{gSums, gSums2}
	} else {
		witnessClaimedEvals = [][]frontend.Variable{fSums}
		witnessBlindingEvals = [][]frontend.Variable{gSums}
	}

	assignment := Circuit{
		IO:                                      []byte(cfg.IOPattern),
		Transcript:                              transcriptT,
		LogNumConstraints:                       cfg.LogNumConstraints,
		WitnessClaimedEvaluations:               witnessClaimedEvals,
		WitnessBlindingEvaluations:              witnessBlindingEvals,
		WitnessLinearStatementEvaluations:       witnessLinearStatementEvaluations,
		HidingSpartanLinearStatementEvaluations: hidingSpartanLinearStatementEvaluations,
		HidingSpartanFirstRound:                 newMerkle(hints.spartanHidingHint.firstRoundMerklePaths.path, false),
		HidingSpartanMerkle:                     newMerkle(hints.spartanHidingHint.roundHints, false),
		WitnessFirstRounds:                      witnessFirstRounds(hints, false),
		WitnessMerkle:                           newMerkle(hints.WitnessRoundHints.roundHints, false),
		NumChallenges:                           cfg.NumChallenges,
		W1Size:                                  cfg.W1Size,
		WHIRParamsWitness:                       NewWhirParams(cfg.WHIRConfigWitness),
		WHIRParamsHidingSpartan:                 NewWhirParams(cfg.WHIRConfigHidingSpartan),
		MatrixA:                                 matrixA,
		MatrixB:                                 matrixB,
		MatrixC:                                 matrixC,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	opts := []backend.ProverOption{
		backend.WithSolverOptions(solver.WithHints(utilities.IndexOf)),
		backend.WithIcicleAcceleration(),
	}

	proof, _ := groth16.Prove(ccs, *pk, witness, opts...)
	err = groth16.Verify(proof, *vk, publicWitness)
	if err != nil {
		log.Printf("Failed to verify proof: %v", err)
		return err
	}
	return nil
}

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

func witnessFirstRounds(hints Hints, isContainer bool) []Merkle {
	result := make([]Merkle, len(hints.WitnessFirstRoundHints))
	for i, hint := range hints.WitnessFirstRoundHints {
		result[i] = newMerkle(hint.path, isContainer)
	}
	return result
}
