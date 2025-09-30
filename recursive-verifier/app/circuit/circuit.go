package circuit

import (
	"fmt"
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

	SPARKIO    []byte
	Transcript []uints.U8 `gnark:",public"`
	WHIRRow    WHIRParams
	WHIRCol    WHIRParams

	PointRow []frontend.Variable
	PointCol []frontend.Variable

	SparkA SPARKMatrixData
	SparkB SPARKMatrixData
	SparkC SPARKMatrixData
}

func (circuit *Circuit) Define(api frontend.API) error {
	sc, arthur, uapi, err := initializeComponents(api, circuit)
	if err != nil {
		return err
	}

	spartanCommitment, err := parseBatchedCommitment(arthur, circuit.WHIRParamsWitness)

	if err != nil {
		return err
	}

	tRand := make([]frontend.Variable, circuit.LogNumConstraints)
	err = arthur.FillChallengeScalars(tRand)
	if err != nil {
		return err
	}

	spartanSumcheckRand, spartanSumcheckLastValue, err := runZKSumcheck(api, sc, uapi, circuit, arthur, frontend.Variable(0), circuit.LogNumConstraints, 4, circuit.WHIRParamsHidingSpartan)
	if err != nil {
		return err
	}

	whirFoldingRandomness, err := RunZKWhir(api, arthur, uapi, sc, circuit.WitnessMerkle, circuit.WitnessFirstRound, circuit.WHIRParamsWitness, [][]frontend.Variable{circuit.WitnessClaimedEvaluations, circuit.WitnessBlindingEvaluations}, circuit.WitnessLinearStatementEvaluations, spartanCommitment,
		[][]frontend.Variable{{}, {}},
		[][]frontend.Variable{},
	)

	if err != nil {
		return err
	}

	x := api.Mul(api.Sub(api.Mul(circuit.WitnessClaimedEvaluations[0], circuit.WitnessClaimedEvaluations[1]), circuit.WitnessClaimedEvaluations[2]), calculateEQ(api, spartanSumcheckRand, tRand))
	api.AssertIsEqual(spartanSumcheckLastValue, x)

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

		err = sparkSingleMatrix(
			api,
			arthur,
			uapi,
			sc,
			circuit.SparkA,
			circuit,
		)
		if err != nil {
			return err
		}

		err = sparkSingleMatrix(
			api,
			arthur,
			uapi,
			sc,
			circuit.SparkB,
			circuit,
		)
		if err != nil {
			return err
		}

		err = sparkSingleMatrix(
			api,
			arthur,
			uapi,
			sc,
			circuit.SparkC,
			circuit,
		)
		if err != nil {
			return err
		}
	} else {
		matrixExtensionEvals := evaluateR1CSMatrixExtension(api, circuit, spartanSumcheckRand, whirFoldingRandomness)

		for i := range 3 {
			api.AssertIsEqual(matrixExtensionEvals[i], circuit.WitnessLinearStatementEvaluations[i])
		}
	}

	return nil
}

func verifyCircuit(
	deferred []Fp256, cfg Config, sparkConfig SparkConfig, hints Hints, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, outputCcsPath string, claimedEvaluations ClaimedEvaluations, internedR1CS R1CS, interner Interner, evaluation string,
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

	acontSparkSumcheckLast := make([]frontend.Variable, 3)
	asparkSumcheckLast := make([]frontend.Variable, 3)
	asparkSumcheckLast[0] = typeConverters.LimbsToBigIntMod(hints.AHints.sparkClaimedEvaluations[0].Limbs)
	asparkSumcheckLast[1] = typeConverters.LimbsToBigIntMod(hints.AHints.sparkClaimedEvaluations[1].Limbs)
	asparkSumcheckLast[2] = typeConverters.LimbsToBigIntMod(hints.AHints.sparkClaimedEvaluations[2].Limbs)

	bcontSparkSumcheckLast := make([]frontend.Variable, 3)
	bsparkSumcheckLast := make([]frontend.Variable, 3)
	bsparkSumcheckLast[0] = typeConverters.LimbsToBigIntMod(hints.BHints.sparkClaimedEvaluations[0].Limbs)
	bsparkSumcheckLast[1] = typeConverters.LimbsToBigIntMod(hints.BHints.sparkClaimedEvaluations[1].Limbs)
	bsparkSumcheckLast[2] = typeConverters.LimbsToBigIntMod(hints.BHints.sparkClaimedEvaluations[2].Limbs)

	ccontSparkSumcheckLast := make([]frontend.Variable, 3)
	csparkSumcheckLast := make([]frontend.Variable, 3)
	csparkSumcheckLast[0] = typeConverters.LimbsToBigIntMod(hints.CHints.sparkClaimedEvaluations[0].Limbs)
	csparkSumcheckLast[1] = typeConverters.LimbsToBigIntMod(hints.CHints.sparkClaimedEvaluations[1].Limbs)
	csparkSumcheckLast[2] = typeConverters.LimbsToBigIntMod(hints.CHints.sparkClaimedEvaluations[2].Limbs)

	contPointRow := make([]frontend.Variable, len(hints.pointRow))
	pointRow := make([]frontend.Variable, len(hints.pointRow))
	for i := range len(hints.pointRow) {
		pointRow[i] = typeConverters.LimbsToBigIntMod(hints.pointRow[i].Limbs)
	}

	contPointCol := make([]frontend.Variable, len(hints.pointCol))
	pointCol := make([]frontend.Variable, len(hints.pointCol))
	for i := range len(hints.pointCol) {
		pointCol[i] = typeConverters.LimbsToBigIntMod(hints.pointCol[i].Limbs)
	}

	fmt.Print(bsparkSumcheckLast)

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

		SPARKIO:         []byte(sparkConfig.IOPattern),
		SPARKTranscript: sparkContTranscript,
		WHIRRow:         NewWhirParams(sparkConfig.WHIRRow),
		WHIRCol:         NewWhirParams(sparkConfig.WHIRCol),

		LogANumTerms: sparkConfig.LogANumTerms,

		PointRow: contPointRow,
		PointCol: contPointCol,

		SparkA: SPARKMatrixData{
			Claimed: typeConverters.LimbsToBigIntMod(hints.AHints.claimed.Limbs),

			SparkSumcheckLast: acontSparkSumcheckLast,

			RowFinalCounter:          typeConverters.LimbsToBigIntMod(hints.AHints.rowFinalCounter.Limbs),
			RowRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.AHints.rowRSAddressEvaluation.Limbs),
			RowRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.AHints.rowRSValueEvaluation.Limbs),
			RowRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.AHints.rowRSTimestampEvaluation.Limbs),

			ColFinalCounter:          typeConverters.LimbsToBigIntMod(hints.AHints.colFinalCounter.Limbs),
			ColRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.AHints.colRSAddressEvaluation.Limbs),
			ColRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.AHints.colRSValueEvaluation.Limbs),
			ColRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.AHints.colRSTimestampEvaluation.Limbs),

			SparkSumcheckFirstRound: newMerkle(hints.AHints.sparkSumcheckData.firstRoundMerklePaths.path, true),
			SparkSumcheckMerkle:     newMerkle(hints.AHints.sparkSumcheckData.roundHints, true),

			RowFinalMerkleFirstRound: newMerkle(hints.AHints.rowFinalMerkle.firstRoundMerklePaths.path, true),
			RowFinalMerkle:           newMerkle(hints.AHints.rowFinalMerkle.roundHints, true),

			RowwiseMerkleFirstRound: newMerkle(hints.AHints.rowwiseSparkMerkle.firstRoundMerklePaths.path, true),
			RowwiseMerkle:           newMerkle(hints.AHints.rowwiseSparkMerkle.roundHints, true),

			ColFinalMerkleFirstRound: newMerkle(hints.AHints.colFinalMerkle.firstRoundMerklePaths.path, true),
			ColFinalMerkle:           newMerkle(hints.AHints.colFinalMerkle.roundHints, true),

			ColwiseMerkleFirstRound: newMerkle(hints.AHints.colwiseSparkMerkle.firstRoundMerklePaths.path, true),
			ColwiseMerkle:           newMerkle(hints.AHints.colwiseSparkMerkle.roundHints, true),

			WHIRA3:       NewWhirParams(sparkConfig.WHIRA3),
			LogANumTerms: sparkConfig.LogANumTerms,
		},

		SparkB: SPARKMatrixData{
			Claimed: typeConverters.LimbsToBigIntMod(hints.BHints.claimed.Limbs),

			SparkSumcheckLast: bcontSparkSumcheckLast,

			RowFinalCounter:          typeConverters.LimbsToBigIntMod(hints.BHints.rowFinalCounter.Limbs),
			RowRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.BHints.rowRSAddressEvaluation.Limbs),
			RowRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.BHints.rowRSValueEvaluation.Limbs),
			RowRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.BHints.rowRSTimestampEvaluation.Limbs),

			ColFinalCounter:          typeConverters.LimbsToBigIntMod(hints.BHints.colFinalCounter.Limbs),
			ColRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.BHints.colRSAddressEvaluation.Limbs),
			ColRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.BHints.colRSValueEvaluation.Limbs),
			ColRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.BHints.colRSTimestampEvaluation.Limbs),

			SparkSumcheckFirstRound: newMerkle(hints.BHints.sparkSumcheckData.firstRoundMerklePaths.path, true),
			SparkSumcheckMerkle:     newMerkle(hints.BHints.sparkSumcheckData.roundHints, true),

			RowFinalMerkleFirstRound: newMerkle(hints.BHints.rowFinalMerkle.firstRoundMerklePaths.path, true),
			RowFinalMerkle:           newMerkle(hints.BHints.rowFinalMerkle.roundHints, true),

			RowwiseMerkleFirstRound: newMerkle(hints.BHints.rowwiseSparkMerkle.firstRoundMerklePaths.path, true),
			RowwiseMerkle:           newMerkle(hints.BHints.rowwiseSparkMerkle.roundHints, true),

			ColFinalMerkleFirstRound: newMerkle(hints.BHints.colFinalMerkle.firstRoundMerklePaths.path, true),
			ColFinalMerkle:           newMerkle(hints.BHints.colFinalMerkle.roundHints, true),

			ColwiseMerkleFirstRound: newMerkle(hints.BHints.colwiseSparkMerkle.firstRoundMerklePaths.path, true),
			ColwiseMerkle:           newMerkle(hints.BHints.colwiseSparkMerkle.roundHints, true),

			WHIRA3:       NewWhirParams(sparkConfig.WHIRB3),
			LogANumTerms: sparkConfig.LogBNumTerms,
		},

		SparkC: SPARKMatrixData{
			Claimed: typeConverters.LimbsToBigIntMod(hints.CHints.claimed.Limbs),

			SparkSumcheckLast: ccontSparkSumcheckLast,

			RowFinalCounter:          typeConverters.LimbsToBigIntMod(hints.CHints.rowFinalCounter.Limbs),
			RowRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.CHints.rowRSAddressEvaluation.Limbs),
			RowRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.CHints.rowRSValueEvaluation.Limbs),
			RowRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.CHints.rowRSTimestampEvaluation.Limbs),

			ColFinalCounter:          typeConverters.LimbsToBigIntMod(hints.CHints.colFinalCounter.Limbs),
			ColRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.CHints.colRSAddressEvaluation.Limbs),
			ColRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.CHints.colRSValueEvaluation.Limbs),
			ColRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.CHints.colRSTimestampEvaluation.Limbs),

			SparkSumcheckFirstRound: newMerkle(hints.CHints.sparkSumcheckData.firstRoundMerklePaths.path, true),
			SparkSumcheckMerkle:     newMerkle(hints.CHints.sparkSumcheckData.roundHints, true),

			RowFinalMerkleFirstRound: newMerkle(hints.CHints.rowFinalMerkle.firstRoundMerklePaths.path, true),
			RowFinalMerkle:           newMerkle(hints.CHints.rowFinalMerkle.roundHints, true),

			RowwiseMerkleFirstRound: newMerkle(hints.CHints.rowwiseSparkMerkle.firstRoundMerklePaths.path, true),
			RowwiseMerkle:           newMerkle(hints.CHints.rowwiseSparkMerkle.roundHints, true),

			ColFinalMerkleFirstRound: newMerkle(hints.CHints.colFinalMerkle.firstRoundMerklePaths.path, true),
			ColFinalMerkle:           newMerkle(hints.CHints.colFinalMerkle.roundHints, true),

			ColwiseMerkleFirstRound: newMerkle(hints.CHints.colwiseSparkMerkle.firstRoundMerklePaths.path, true),
			ColwiseMerkle:           newMerkle(hints.CHints.colwiseSparkMerkle.roundHints, true),

			WHIRA3:       NewWhirParams(sparkConfig.WHIRC3),
			LogANumTerms: sparkConfig.LogCNumTerms,
		},

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

		SPARKIO:         []byte(sparkConfig.IOPattern),
		SPARKTranscript: sparkTranscriptT,
		WHIRRow:         NewWhirParams(sparkConfig.WHIRRow),
		WHIRCol:         NewWhirParams(sparkConfig.WHIRCol),
		LogANumTerms:    sparkConfig.LogANumTerms,

		PointRow: pointRow,
		PointCol: pointCol,

		SparkA: SPARKMatrixData{
			Claimed: typeConverters.LimbsToBigIntMod(hints.AHints.claimed.Limbs),

			SparkSumcheckLast: asparkSumcheckLast,

			RowFinalCounter:          typeConverters.LimbsToBigIntMod(hints.AHints.rowFinalCounter.Limbs),
			RowRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.AHints.rowRSAddressEvaluation.Limbs),
			RowRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.AHints.rowRSValueEvaluation.Limbs),
			RowRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.AHints.rowRSTimestampEvaluation.Limbs),

			ColFinalCounter:          typeConverters.LimbsToBigIntMod(hints.AHints.colFinalCounter.Limbs),
			ColRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.AHints.colRSAddressEvaluation.Limbs),
			ColRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.AHints.colRSValueEvaluation.Limbs),
			ColRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.AHints.colRSTimestampEvaluation.Limbs),

			SparkSumcheckFirstRound: newMerkle(hints.AHints.sparkSumcheckData.firstRoundMerklePaths.path, false),
			SparkSumcheckMerkle:     newMerkle(hints.AHints.sparkSumcheckData.roundHints, false),

			RowFinalMerkleFirstRound: newMerkle(hints.AHints.rowFinalMerkle.firstRoundMerklePaths.path, false),
			RowFinalMerkle:           newMerkle(hints.AHints.rowFinalMerkle.roundHints, false),

			RowwiseMerkleFirstRound: newMerkle(hints.AHints.rowwiseSparkMerkle.firstRoundMerklePaths.path, false),
			RowwiseMerkle:           newMerkle(hints.AHints.rowwiseSparkMerkle.roundHints, false),

			ColFinalMerkleFirstRound: newMerkle(hints.AHints.colFinalMerkle.firstRoundMerklePaths.path, false),
			ColFinalMerkle:           newMerkle(hints.AHints.colFinalMerkle.roundHints, false),

			ColwiseMerkleFirstRound: newMerkle(hints.AHints.colwiseSparkMerkle.firstRoundMerklePaths.path, false),
			ColwiseMerkle:           newMerkle(hints.AHints.colwiseSparkMerkle.roundHints, false),

			WHIRA3:       NewWhirParams(sparkConfig.WHIRA3),
			LogANumTerms: sparkConfig.LogANumTerms,
		},

		SparkB: SPARKMatrixData{
			Claimed: typeConverters.LimbsToBigIntMod(hints.BHints.claimed.Limbs),

			SparkSumcheckLast: bsparkSumcheckLast,

			RowFinalCounter:          typeConverters.LimbsToBigIntMod(hints.BHints.rowFinalCounter.Limbs),
			RowRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.BHints.rowRSAddressEvaluation.Limbs),
			RowRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.BHints.rowRSValueEvaluation.Limbs),
			RowRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.BHints.rowRSTimestampEvaluation.Limbs),

			ColFinalCounter:          typeConverters.LimbsToBigIntMod(hints.BHints.colFinalCounter.Limbs),
			ColRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.BHints.colRSAddressEvaluation.Limbs),
			ColRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.BHints.colRSValueEvaluation.Limbs),
			ColRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.BHints.colRSTimestampEvaluation.Limbs),

			SparkSumcheckFirstRound: newMerkle(hints.BHints.sparkSumcheckData.firstRoundMerklePaths.path, false),
			SparkSumcheckMerkle:     newMerkle(hints.BHints.sparkSumcheckData.roundHints, false),

			RowFinalMerkleFirstRound: newMerkle(hints.BHints.rowFinalMerkle.firstRoundMerklePaths.path, false),
			RowFinalMerkle:           newMerkle(hints.BHints.rowFinalMerkle.roundHints, false),

			RowwiseMerkleFirstRound: newMerkle(hints.BHints.rowwiseSparkMerkle.firstRoundMerklePaths.path, false),
			RowwiseMerkle:           newMerkle(hints.BHints.rowwiseSparkMerkle.roundHints, false),

			ColFinalMerkleFirstRound: newMerkle(hints.BHints.colFinalMerkle.firstRoundMerklePaths.path, false),
			ColFinalMerkle:           newMerkle(hints.BHints.colFinalMerkle.roundHints, false),

			ColwiseMerkleFirstRound: newMerkle(hints.BHints.colwiseSparkMerkle.firstRoundMerklePaths.path, false),
			ColwiseMerkle:           newMerkle(hints.BHints.colwiseSparkMerkle.roundHints, false),

			WHIRA3:       NewWhirParams(sparkConfig.WHIRB3),
			LogANumTerms: sparkConfig.LogBNumTerms,
		},

		SparkC: SPARKMatrixData{
			Claimed: typeConverters.LimbsToBigIntMod(hints.CHints.claimed.Limbs),

			SparkSumcheckLast: csparkSumcheckLast,

			RowFinalCounter:          typeConverters.LimbsToBigIntMod(hints.CHints.rowFinalCounter.Limbs),
			RowRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.CHints.rowRSAddressEvaluation.Limbs),
			RowRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.CHints.rowRSValueEvaluation.Limbs),
			RowRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.CHints.rowRSTimestampEvaluation.Limbs),

			ColFinalCounter:          typeConverters.LimbsToBigIntMod(hints.CHints.colFinalCounter.Limbs),
			ColRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.CHints.colRSAddressEvaluation.Limbs),
			ColRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.CHints.colRSValueEvaluation.Limbs),
			ColRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.CHints.colRSTimestampEvaluation.Limbs),

			SparkSumcheckFirstRound: newMerkle(hints.CHints.sparkSumcheckData.firstRoundMerklePaths.path, false),
			SparkSumcheckMerkle:     newMerkle(hints.CHints.sparkSumcheckData.roundHints, false),

			RowFinalMerkleFirstRound: newMerkle(hints.CHints.rowFinalMerkle.firstRoundMerklePaths.path, false),
			RowFinalMerkle:           newMerkle(hints.CHints.rowFinalMerkle.roundHints, false),

			RowwiseMerkleFirstRound: newMerkle(hints.CHints.rowwiseSparkMerkle.firstRoundMerklePaths.path, false),
			RowwiseMerkle:           newMerkle(hints.CHints.rowwiseSparkMerkle.roundHints, false),

			ColFinalMerkleFirstRound: newMerkle(hints.CHints.colFinalMerkle.firstRoundMerklePaths.path, false),
			ColFinalMerkle:           newMerkle(hints.CHints.colFinalMerkle.roundHints, false),

			ColwiseMerkleFirstRound: newMerkle(hints.CHints.colwiseSparkMerkle.firstRoundMerklePaths.path, false),
			ColwiseMerkle:           newMerkle(hints.CHints.colwiseSparkMerkle.roundHints, false),

			WHIRA3:       NewWhirParams(sparkConfig.WHIRC3),
			LogANumTerms: sparkConfig.LogCNumTerms,
		},

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

func gpaSumcheckVerifier(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	layerCount int,
) (GPASumcheckResult, error) {
	l := make([]frontend.Variable, 2)
	r := make([]frontend.Variable, 1)

	gpaClaimedValues := make([]frontend.Variable, 2)
	err := arthur.FillNextScalars(gpaClaimedValues)
	if err != nil {
		return GPASumcheckResult{}, err
	}
	err = arthur.FillChallengeScalars(r)
	if err != nil {
		return GPASumcheckResult{}, err
	}
	lastEval := utilities.UnivarPoly(api, gpaClaimedValues, r)[0]
	prevRand := []frontend.Variable{r[0]}
	var rand []frontend.Variable

	for i := 1; i < (layerCount - 1); i++ {
		rand, lastEval, err = runSumcheck(
			api,
			arthur,
			lastEval,
			i,
			4,
		)
		if err != nil {
			return GPASumcheckResult{}, err
		}

		err = arthur.FillNextScalars(l)
		if err != nil {
			return GPASumcheckResult{}, err
		}
		err = arthur.FillChallengeScalars(r)
		if err != nil {
			return GPASumcheckResult{}, err
		}
		claimedLastSch := api.Mul(
			calculateEQ(api, prevRand, rand),
			utilities.UnivarPoly(api, l, []frontend.Variable{0})[0],
			utilities.UnivarPoly(api, l, []frontend.Variable{1})[0],
		)
		api.AssertIsEqual(claimedLastSch, lastEval)
		prevRand = append(rand, r[0])
		lastEval = utilities.UnivarPoly(api, l, []frontend.Variable{r[0]})[0]
	}

	return GPASumcheckResult{
		claimedProducts:   gpaClaimedValues,
		lastSumcheckValue: lastEval,
		randomness:        prevRand,
	}, nil
}

type GPASumcheckResult struct {
	claimedProducts   []frontend.Variable
	lastSumcheckValue frontend.Variable
	randomness        []frontend.Variable
}

func CalculateAdr(api frontend.API, coefficients []frontend.Variable) frontend.Variable {
	ans := frontend.Variable(0)
	for _, coefficient := range coefficients {
		ans = api.Add(api.Mul(ans, 2), coefficient)
	}

	return ans
}

func sparkSingleMatrix(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
	matrix SPARKMatrixData,
	circuit *Circuit,
) error {
	sumcheckCommitment, err := parseBatchedCommitment(arthur, matrix.WHIRA3)
	if err != nil {
		return err
	}
	rowwiseCommitment, err := parseBatchedCommitment(arthur, matrix.WHIRA3)
	if err != nil {
		return err
	}
	colwiseCommitment, err := parseBatchedCommitment(arthur, matrix.WHIRA3)
	if err != nil {
		return err
	}

	rowFinalCommitment, err := parseBatchedCommitment(arthur, circuit.WHIRRow)
	if err != nil {
		return err
	}
	colFinalCommitment, err := parseBatchedCommitment(arthur, circuit.WHIRCol)
	if err != nil {
		return err
	}

	// After debug: Change 1 to actual claimed value
	sparkSumcheckFoldingRandomness, sparkSumcheckLastEval, err := runSumcheck(api, arthur, matrix.Claimed, matrix.LogANumTerms, 4)
	if err != nil {
		return err
	}

	api.AssertIsEqual(sparkSumcheckLastEval, api.Mul(matrix.SparkSumcheckLast[0], matrix.SparkSumcheckLast[1], matrix.SparkSumcheckLast[2]))

	_, err = RunZKWhir(api, arthur, uapi, sc, matrix.SparkSumcheckMerkle, matrix.SparkSumcheckFirstRound, matrix.WHIRA3, [][]frontend.Variable{{}, {}, {}}, []frontend.Variable{}, sumcheckCommitment,
		[][]frontend.Variable{{matrix.SparkSumcheckLast[0]}, {matrix.SparkSumcheckLast[1]}, {matrix.SparkSumcheckLast[2]}},
		[][]frontend.Variable{sparkSumcheckFoldingRandomness},
	)
	if err != nil {
		return err
	}

	// Rowwise

	tauGammaTemp := make([]frontend.Variable, 2)
	if err := arthur.FillChallengeScalars(tauGammaTemp); err != nil {
		return err
	}
	tau := tauGammaTemp[0]
	gamma := tauGammaTemp[1]

	// Change this debug statement
	gpaResult, err := gpaSumcheckVerifier(api, arthur, len(circuit.PointRow)+2)
	if err != nil {
		return err
	}

	claimedInit := gpaResult.claimedProducts[0]
	claimedFinal := gpaResult.claimedProducts[1]

	last_randomness := gpaResult.randomness[0]
	evaluation_randomness := gpaResult.randomness[1:]

	addr := CalculateAdr(api, evaluation_randomness)
	mem := calculateEQ(api, circuit.PointRow, evaluation_randomness)
	init_cntr := 0

	init_opening := api.Sub(api.Add(api.Mul(addr, gamma, gamma), api.Mul(mem, gamma), init_cntr), tau)

	_, err = RunZKWhir(api, arthur, uapi, sc, matrix.RowFinalMerkle, matrix.RowFinalMerkleFirstRound, circuit.WHIRRow, [][]frontend.Variable{{}}, []frontend.Variable{}, rowFinalCommitment,
		[][]frontend.Variable{{matrix.RowFinalCounter}},
		[][]frontend.Variable{evaluation_randomness},
	)
	if err != nil {
		return err
	}

	final_opening := api.Sub(api.Add(api.Mul(addr, gamma, gamma), api.Mul(mem, gamma), matrix.RowFinalCounter), tau)

	evaluated_value := api.Add(api.Mul(init_opening, api.Sub(1, last_randomness)), api.Mul(final_opening, last_randomness))

	api.AssertIsEqual(gpaResult.lastSumcheckValue, evaluated_value)

	// Change this after debug
	gpaResultRSWS, err := gpaSumcheckVerifier(api, arthur, matrix.LogANumTerms+2)
	if err != nil {
		return err
	}

	claimedRS := gpaResultRSWS.claimedProducts[0]
	claimedWS := gpaResultRSWS.claimedProducts[1]

	rsws_last_randomness := gpaResultRSWS.randomness[0]
	rsws_evaluation_randomness := gpaResultRSWS.randomness[1:]

	rs_opening := api.Sub(api.Add(api.Mul(matrix.RowRSAddressEvaluation, gamma, gamma), api.Mul(matrix.RowRSValueEvaluation, gamma), matrix.RowRSTimestampEvaluation), tau)
	ws_opening := api.Sub(api.Add(api.Mul(matrix.RowRSAddressEvaluation, gamma, gamma), api.Mul(matrix.RowRSValueEvaluation, gamma), matrix.RowRSTimestampEvaluation, 1), tau)

	rsws_evaluated_value := api.Add(api.Mul(rs_opening, api.Sub(1, rsws_last_randomness)), api.Mul(ws_opening, rsws_last_randomness))

	api.AssertIsEqual(gpaResultRSWS.lastSumcheckValue, rsws_evaluated_value)

	_, err = RunZKWhir(api, arthur, uapi, sc, matrix.RowwiseMerkle, matrix.RowwiseMerkleFirstRound, matrix.WHIRA3, [][]frontend.Variable{{}}, []frontend.Variable{}, rowwiseCommitment,
		[][]frontend.Variable{{matrix.RowRSAddressEvaluation}, {matrix.RowRSValueEvaluation}, {matrix.RowRSTimestampEvaluation}},
		[][]frontend.Variable{rsws_evaluation_randomness},
	)
	if err != nil {
		return err
	}

	api.AssertIsEqual(api.Mul(claimedInit, claimedWS), api.Mul(claimedRS, claimedFinal))

	// Colwise

	colwiseTauGammaTemp := make([]frontend.Variable, 2)
	if err := arthur.FillChallengeScalars(colwiseTauGammaTemp); err != nil {
		return err
	}
	colwiseTau := colwiseTauGammaTemp[0]
	colwiseGamma := colwiseTauGammaTemp[1]

	// Change this debug statement
	colwiseInitFinalGpaResult, err := gpaSumcheckVerifier(api, arthur, len(circuit.PointCol)-1+2)
	if err != nil {
		return err
	}

	colwiseClaimedInit := colwiseInitFinalGpaResult.claimedProducts[0]
	colwiseClaimedFinal := colwiseInitFinalGpaResult.claimedProducts[1]

	colwiseLast_randomness := colwiseInitFinalGpaResult.randomness[0]
	colwiseEvaluation_randomness := colwiseInitFinalGpaResult.randomness[1:]

	colwiseaddr := CalculateAdr(api, colwiseEvaluation_randomness)

	colwisemem := api.Mul(calculateEQ(api, circuit.PointCol[1:], colwiseEvaluation_randomness), api.Sub(1, circuit.PointCol[0]))
	colwiseinit_cntr := 0

	colwiseinit_opening := api.Sub(api.Add(api.Mul(colwiseaddr, colwiseGamma, colwiseGamma), api.Mul(colwisemem, colwiseGamma), colwiseinit_cntr), colwiseTau)

	_, err = RunZKWhir(api, arthur, uapi, sc, circuit.SparkA.ColFinalMerkle, circuit.SparkA.ColFinalMerkleFirstRound, circuit.WHIRCol, [][]frontend.Variable{{}}, []frontend.Variable{}, colFinalCommitment,
		[][]frontend.Variable{{matrix.ColFinalCounter}},
		[][]frontend.Variable{colwiseEvaluation_randomness},
	)
	if err != nil {
		return err
	}

	colwisefinal_opening := api.Sub(api.Add(api.Mul(colwiseaddr, colwiseGamma, colwiseGamma), api.Mul(colwisemem, colwiseGamma), matrix.ColFinalCounter), colwiseTau)
	colwiseevaluated_value := api.Add(api.Mul(colwiseinit_opening, api.Sub(1, colwiseLast_randomness)), api.Mul(colwisefinal_opening, colwiseLast_randomness))
	api.AssertIsEqual(colwiseInitFinalGpaResult.lastSumcheckValue, colwiseevaluated_value)

	// Colwise RS WS
	colwisegpaResultRSWS, err := gpaSumcheckVerifier(api, arthur, matrix.LogANumTerms+2)
	if err != nil {
		return err
	}

	colwiseClaimedRS := colwisegpaResultRSWS.claimedProducts[0]
	colwiseClaimedWS := colwisegpaResultRSWS.claimedProducts[1]

	colwisersws_last_randomness := colwisegpaResultRSWS.randomness[0]
	colwisersws_evaluation_randomness := colwisegpaResultRSWS.randomness[1:]

	colwisers_opening := api.Sub(api.Add(api.Mul(matrix.ColRSAddressEvaluation, colwiseGamma, colwiseGamma), api.Mul(matrix.ColRSValueEvaluation, colwiseGamma), matrix.ColRSTimestampEvaluation), colwiseTau)
	colwisews_opening := api.Sub(api.Add(api.Mul(matrix.ColRSAddressEvaluation, colwiseGamma, colwiseGamma), api.Mul(matrix.ColRSValueEvaluation, colwiseGamma), matrix.ColRSTimestampEvaluation, 1), colwiseTau)

	colwisersws_evaluated_value := api.Add(api.Mul(colwisers_opening, api.Sub(1, colwisersws_last_randomness)), api.Mul(colwisews_opening, colwisersws_last_randomness))

	api.AssertIsEqual(colwisegpaResultRSWS.lastSumcheckValue, colwisersws_evaluated_value)

	_, err = RunZKWhir(api, arthur, uapi, sc, matrix.ColwiseMerkle, matrix.ColwiseMerkleFirstRound, matrix.WHIRA3, [][]frontend.Variable{{}}, []frontend.Variable{}, colwiseCommitment,
		[][]frontend.Variable{{matrix.ColRSAddressEvaluation}, {matrix.ColRSValueEvaluation}, {matrix.ColRSTimestampEvaluation}},
		[][]frontend.Variable{colwisersws_evaluation_randomness},
	)
	if err != nil {
		return err
	}

	api.AssertIsEqual(api.Mul(colwiseClaimedInit, colwiseClaimedWS), api.Mul(colwiseClaimedRS, colwiseClaimedFinal))

	return nil
}
