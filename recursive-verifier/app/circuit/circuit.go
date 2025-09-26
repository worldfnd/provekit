package circuit

import (
	"log"
	"os"

	"reilabs/whir-verifier-circuit/app/typeConverters"
	"reilabs/whir-verifier-circuit/app/utilities"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

type Circuit struct {
	// Inputs
	WitnessLinearStatementEvaluations       []frontend.Variable
	HidingSpartanLinearStatementEvaluations []frontend.Variable
	LogNumConstraints                       int
	LogNumVariables                         int
	LogANumTerms                            int
	WitnessClaimedEvaluations               []frontend.Variable
	WitnessBlindingEvaluations              []frontend.Variable
	HidingSpartanFirstRound                 Merkle
	HidingSpartanMerkle                     Merkle
	WitnessMerkle                           Merkle
	WitnessFirstRound                       Merkle
	WHIRParamsWitness                       WHIRParams
	// Is this not used?
	WHIRParamsHidingSpartan WHIRParams

	MatrixA []MatrixCell
	MatrixB []MatrixCell
	MatrixC []MatrixCell
	// Public Input

	IO              []byte
	UseSpark        bool
	SPARKTranscript []uints.U8 `gnark:",public"`

	SPARKIO                 []byte
	Transcript              []uints.U8 `gnark:",public"`
	WHIRA3                  WHIRParams
	WHIRRow                 WHIRParams
	WHIRCol                 WHIRParams
	SparkSumcheckFirstRound Merkle
	SparkSumcheckMerkle     Merkle
	AClaimed                frontend.Variable
	SparkSumcheckLast       []frontend.Variable
}

func (circuit *Circuit) Define(api frontend.API) error {
	// sc, arthur, uapi, err := initializeComponents(api, circuit)
	// if err != nil {
	// 	return err
	// }

	// rootHash, batchingRandomness, initialOODQueries, initialOODAnswers, err := parseBatchedCommitment(arthur, circuit.WHIRParamsWitness)

	// if err != nil {
	// 	return err
	// }

	// tRand := make([]frontend.Variable, circuit.LogNumConstraints)
	// err = arthur.FillChallengeScalars(tRand)
	// if err != nil {
	// 	return err
	// }

	// spartanSumcheckRand, spartanSumcheckLastValue, err := runZKSumcheck(api, sc, uapi, circuit, arthur, frontend.Variable(0), circuit.LogNumConstraints, 4, circuit.WHIRParamsHidingSpartan)
	// if err != nil {
	// 	return err
	// }

	// _ = spartanSumcheckRand
	// _ = spartanSumcheckLastValue

	// whirFoldingRandomness, err := RunZKWhir(api, arthur, uapi, sc, circuit.WitnessMerkle, circuit.WitnessFirstRound, circuit.WHIRParamsWitness, [][]frontend.Variable{circuit.WitnessClaimedEvaluations, circuit.WitnessBlindingEvaluations}, circuit.WitnessLinearStatementEvaluations, batchingRandomness, initialOODQueries, initialOODAnswers, rootHash,
	// 	[][]frontend.Variable{{}, {}},
	// 	[][]frontend.Variable{},
	// )

	// if err != nil {
	// 	return err
	// }

	// _ = whirFoldingRandomness

	// _ = rootHash
	// _ = batchingRandomness
	// _ = initialOODQueries
	// _ = initialOODAnswers
	// _ = sc
	// _ = uapi

	// x := api.Mul(api.Sub(api.Mul(circuit.WitnessClaimedEvaluations[0], circuit.WitnessClaimedEvaluations[1]), circuit.WitnessClaimedEvaluations[2]), calculateEQ(api, spartanSumcheckRand, tRand))
	// api.AssertIsEqual(spartanSumcheckLastValue, x)

	if circuit.UseSpark {
		sc := skyscraper.NewSkyscraper(api, 2)
		arthur, err := gnarkNimue.NewSkyscraperArthur(api, sc, circuit.SPARKIO, circuit.SPARKTranscript[:], true)
		if err != nil {
			return err
		}
		uapi, err := uints.New[uints.U64](api)
		if err != nil {
			return err
		}

		// TODO: create a commitment struct
		sumcheckRootHash, sumcheckBatchingRandomness, sumcheckInitialOODQueries, sumcheckInitialOODAnswers, err := parseBatchedCommitment(arthur, circuit.WHIRA3)
		if err != nil {
			return err
		}
		rowwiseRootHash, rowwiseBatchingRandomness, rowwiseInitialOODQueries, rowwiseInitialOODAnswers, err := parseBatchedCommitment(arthur, circuit.WHIRA3)
		if err != nil {
			return err
		}
		colwiseRootHash, colwiseBatchingRandomness, colwiseInitialOODQueries, colwiseInitialOODAnswers, err := parseBatchedCommitment(arthur, circuit.WHIRA3)
		if err != nil {
			return err
		}

		rowFinaltsRootHash, rowFinaltsBatchingRandomness, rowFinaltsInitialOODQueries, rowFinaltsInitialOODAnswers, err := parseBatchedCommitment(arthur, circuit.WHIRRow)
		if err != nil {
			return err
		}
		colFinaltsRootHash, colFinaltsBatchingRandomness, colFinaltsInitialOODQueries, colFinaltsInitialOODAnswers, err := parseBatchedCommitment(arthur, circuit.WHIRCol)
		if err != nil {
			return err
		}

		// After debug: Change 1 to actual claimed value
		sparkSumcheckFoldingRandomness, sparkSumcheckLastEval, err := runSumcheck(api, arthur, 1, circuit.LogANumTerms, 4)
		if err != nil {
			return err
		}

		_ = sparkSumcheckFoldingRandomness
		_ = sparkSumcheckLastEval

		whirFoldingRandomness, err := RunZKWhir(api, arthur, uapi, sc, circuit.SparkSumcheckMerkle, circuit.SparkSumcheckFirstRound, circuit.WHIRA3, [][]frontend.Variable{{}, {}, {}}, []frontend.Variable{}, sumcheckBatchingRandomness, sumcheckInitialOODQueries, sumcheckInitialOODAnswers, sumcheckRootHash,
			[][]frontend.Variable{{circuit.SparkSumcheckLast[0]}, {circuit.SparkSumcheckLast[1]}, {circuit.SparkSumcheckLast[2]}},
			[][]frontend.Variable{sparkSumcheckFoldingRandomness},
		)
		if err != nil {
			return err
		}

		tauGammaTemp := make([]frontend.Variable, 2)
		if err := arthur.FillChallengeScalars(tauGammaTemp); err != nil {
			return err
		}
		tau := tauGammaTemp[0]
		gamma := tauGammaTemp[1]

		_ = tau
		_ = gamma

		_ = whirFoldingRandomness

		_ = sumcheckRootHash
		_ = sumcheckBatchingRandomness
		_ = sumcheckInitialOODAnswers
		_ = sumcheckInitialOODQueries

		_ = rowwiseRootHash
		_ = rowwiseBatchingRandomness
		_ = rowwiseInitialOODAnswers
		_ = rowwiseInitialOODQueries

		_ = colwiseRootHash
		_ = colwiseBatchingRandomness
		_ = colwiseInitialOODAnswers
		_ = colwiseInitialOODQueries

		_ = rowFinaltsRootHash
		_ = rowFinaltsBatchingRandomness
		_ = rowFinaltsInitialOODAnswers
		_ = rowFinaltsInitialOODQueries

		_ = colFinaltsRootHash
		_ = colFinaltsBatchingRandomness
		_ = colFinaltsInitialOODAnswers
		_ = colFinaltsInitialOODQueries

		_ = uapi
	} else {
		// matrixExtensionEvals := evaluateR1CSMatrixExtension(api, circuit, spartanSumcheckRand, whirFoldingRandomness)

		// for i := range 3 {
		// 	api.AssertIsEqual(matrixExtensionEvals[i], circuit.WitnessLinearStatementEvaluations[i])
		// }
	}

	return nil
}

func verifyCircuit(
	deferred []Fp256, cfg Config, sparkConfig SparkConfig, hints Hints, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, outputCcsPath string, claimedEvaluations ClaimedEvaluations, internedR1CS R1CS, interner Interner, evaluation string, sparkSumcheck []Fp256,
) error {
	transcriptT := make([]uints.U8, cfg.TranscriptLen)
	contTranscript := make([]uints.U8, cfg.TranscriptLen)

	for i := range cfg.Transcript {
		transcriptT[i] = uints.NewU8(cfg.Transcript[i])
	}

	sparkTranscriptT := make([]uints.U8, len(sparkConfig.Transcript))
	sparkContTranscript := make([]uints.U8, len(sparkConfig.Transcript))

	for i := range sparkConfig.Transcript {
		sparkTranscriptT[i] = uints.NewU8(sparkConfig.Transcript[i])
	}

	witnessLinearStatementEvaluations := make([]frontend.Variable, 3)
	hidingSpartanLinearStatementEvaluations := make([]frontend.Variable, 1)
	contWitnessLinearStatementEvaluations := make([]frontend.Variable, 3)
	contHidingSpartanLinearStatementEvaluations := make([]frontend.Variable, 1)

	hidingSpartanLinearStatementEvaluations[0] = typeConverters.LimbsToBigIntMod(deferred[0].Limbs)
	witnessLinearStatementEvaluations[0] = typeConverters.LimbsToBigIntMod(deferred[1].Limbs)
	witnessLinearStatementEvaluations[1] = typeConverters.LimbsToBigIntMod(deferred[2].Limbs)
	witnessLinearStatementEvaluations[2] = typeConverters.LimbsToBigIntMod(deferred[3].Limbs)

	contSparkSumcheckLast := make([]frontend.Variable, 3)
	sparkSumcheckLast := make([]frontend.Variable, 3)
	sparkSumcheckLast[0] = typeConverters.LimbsToBigIntMod(sparkSumcheck[0].Limbs)
	sparkSumcheckLast[1] = typeConverters.LimbsToBigIntMod(sparkSumcheck[1].Limbs)
	sparkSumcheckLast[2] = typeConverters.LimbsToBigIntMod(sparkSumcheck[2].Limbs)

	fSums, gSums := parseClaimedEvaluations(claimedEvaluations, true)

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

	useSpark := evaluation == "spark"
	//
	var circuit = Circuit{
		IO:                                      []byte(cfg.IOPattern),
		Transcript:                              contTranscript,
		LogNumConstraints:                       cfg.LogNumConstraints,
		WitnessClaimedEvaluations:               fSums,
		WitnessBlindingEvaluations:              gSums,
		WitnessLinearStatementEvaluations:       contWitnessLinearStatementEvaluations,
		HidingSpartanLinearStatementEvaluations: contHidingSpartanLinearStatementEvaluations,
		HidingSpartanFirstRound:                 newMerkle(hints.spartanHidingHint.firstRoundMerklePaths.path, true),
		HidingSpartanMerkle:                     newMerkle(hints.spartanHidingHint.roundHints, true),
		WitnessMerkle:                           newMerkle(hints.witnessHints.roundHints, true),
		WitnessFirstRound:                       newMerkle(hints.witnessHints.firstRoundMerklePaths.path, true),

		WHIRParamsWitness:       NewWhirParams(cfg.WHIRConfigWitness),
		WHIRParamsHidingSpartan: NewWhirParams(cfg.WHIRConfigHidingSpartan),

		MatrixA: matrixA,
		MatrixB: matrixB,
		MatrixC: matrixC,

		SPARKIO:                 []byte(sparkConfig.IOPattern),
		SPARKTranscript:         sparkContTranscript,
		WHIRA3:                  NewWhirParams(sparkConfig.WHIRA3),
		WHIRRow:                 NewWhirParams(sparkConfig.WHIRRow),
		WHIRCol:                 NewWhirParams(sparkConfig.WHIRCol),
		SparkSumcheckFirstRound: newMerkle(hints.sparkSumcheckData.firstRoundMerklePaths.path, true),
		SparkSumcheckMerkle:     newMerkle(hints.sparkSumcheckData.roundHints, true),
		LogANumTerms:            sparkConfig.LogANumTerms,
		AClaimed:                sparkConfig.AClaimed,
		SparkSumcheckLast:       contSparkSumcheckLast,

		UseSpark: useSpark,
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("Failed to compile circuit: %v", err)
	}
	if outputCcsPath != "" {
		ccsFile, err := os.Create(outputCcsPath)
		if err != nil {
			log.Printf("Cannot create ccs file %s: %v", outputCcsPath, err)
		} else {
			_, err = ccs.WriteTo(ccsFile)
			if err != nil {
				log.Printf("Cannot write ccs file %s: %v", outputCcsPath, err)
			}
		}
		log.Printf("ccs written to %s", outputCcsPath)
	}

	if pk == nil || vk == nil {
		log.Printf("PK/VK not provided, generating new keys unsafely. Consider providing keys from an MPC ceremony.")
		unsafePk, unsafeVk, err := groth16.Setup(ccs)
		if err != nil {
			log.Fatalf("Failed to setup groth16: %v", err)
		}
		pk = &unsafePk
		vk = &unsafeVk
	}

	fSums, gSums = parseClaimedEvaluations(claimedEvaluations, false)

	assignment := Circuit{
		IO:                []byte(cfg.IOPattern),
		Transcript:        transcriptT,
		LogNumConstraints: cfg.LogNumConstraints,

		WitnessClaimedEvaluations:               fSums,
		WitnessBlindingEvaluations:              gSums,
		WitnessLinearStatementEvaluations:       witnessLinearStatementEvaluations,
		HidingSpartanLinearStatementEvaluations: hidingSpartanLinearStatementEvaluations,

		HidingSpartanFirstRound: newMerkle(hints.spartanHidingHint.firstRoundMerklePaths.path, false),
		HidingSpartanMerkle:     newMerkle(hints.spartanHidingHint.roundHints, false),
		WitnessMerkle:           newMerkle(hints.witnessHints.roundHints, false),
		WitnessFirstRound:       newMerkle(hints.witnessHints.firstRoundMerklePaths.path, false),

		WHIRParamsWitness:       NewWhirParams(cfg.WHIRConfigWitness),
		WHIRParamsHidingSpartan: NewWhirParams(cfg.WHIRConfigHidingSpartan),

		MatrixA: matrixA,
		MatrixB: matrixB,
		MatrixC: matrixC,

		SPARKIO:                 []byte(sparkConfig.IOPattern),
		SPARKTranscript:         sparkTranscriptT,
		WHIRA3:                  NewWhirParams(sparkConfig.WHIRA3),
		WHIRRow:                 NewWhirParams(sparkConfig.WHIRRow),
		WHIRCol:                 NewWhirParams(sparkConfig.WHIRCol),
		SparkSumcheckFirstRound: newMerkle(hints.sparkSumcheckData.firstRoundMerklePaths.path, false),
		SparkSumcheckMerkle:     newMerkle(hints.sparkSumcheckData.roundHints, false),
		LogANumTerms:            sparkConfig.LogANumTerms,
		AClaimed:                sparkConfig.AClaimed,
		SparkSumcheckLast:       sparkSumcheckLast,

		UseSpark: useSpark,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, *pk, witness, backend.WithSolverOptions(solver.WithHints(utilities.IndexOf)))
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
