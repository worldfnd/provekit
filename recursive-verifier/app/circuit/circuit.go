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
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

type Circuit struct {
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
	WHIRParamsHidingSpartan                 WHIRParams

	MatrixA []MatrixCell
	MatrixB []MatrixCell
	MatrixC []MatrixCell

	IO              []byte
	UseSpark        bool
	SPARKTranscript []uints.U8

	SPARKIO    []byte
	Transcript []uints.U8

	WHIRRow WHIRParams
	WHIRCol WHIRParams

	PointRow []frontend.Variable
	PointCol []frontend.Variable

	SparkRLC SPARKMatrixData
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
			circuit.SparkRLC,
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
	deferred []Fp256, cfg Config, sparkConfig SparkConfig, hints Hints, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, claimedEvaluations ClaimedEvaluations, internedR1CS R1CS, interner Interner, buildOps common.BuildOps,
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

	contSparkSumcheckLast := make([]frontend.Variable, 5)
	sparkSumcheckLast := make([]frontend.Variable, 5)
	sparkSumcheckLast[0] = typeConverters.LimbsToBigIntMod(hints.SparkHints.sparkClaimedEvaluations[0].Limbs)
	sparkSumcheckLast[1] = typeConverters.LimbsToBigIntMod(hints.SparkHints.sparkClaimedEvaluations[1].Limbs)
	sparkSumcheckLast[2] = typeConverters.LimbsToBigIntMod(hints.SparkHints.sparkClaimedEvaluations[2].Limbs)
	sparkSumcheckLast[3] = typeConverters.LimbsToBigIntMod(hints.SparkHints.sparkClaimedEvaluations[3].Limbs)
	sparkSumcheckLast[4] = typeConverters.LimbsToBigIntMod(hints.SparkHints.sparkClaimedEvaluations[4].Limbs)

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

	useSpark := buildOps.Evaluation == "spark"

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

		LogANumTerms: sparkConfig.LogNumTerms,

		PointRow: contPointRow,
		PointCol: contPointCol,

		SparkRLC: SPARKMatrixData{
			Claimed: typeConverters.LimbsToBigIntMod(hints.SparkHints.claimed.Limbs),

			SparkSumcheckLast: contSparkSumcheckLast,

			RowFinalCounter:          typeConverters.LimbsToBigIntMod(hints.SparkHints.rowFinalCounter.Limbs),
			RowRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.SparkHints.rowRSAddressEvaluation.Limbs),
			RowRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.SparkHints.rowRSValueEvaluation.Limbs),
			RowRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.SparkHints.rowRSTimestampEvaluation.Limbs),

			ColFinalCounter:          typeConverters.LimbsToBigIntMod(hints.SparkHints.colFinalCounter.Limbs),
			ColRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.SparkHints.colRSAddressEvaluation.Limbs),
			ColRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.SparkHints.colRSValueEvaluation.Limbs),
			ColRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.SparkHints.colRSTimestampEvaluation.Limbs),

			EvaluesSumcheckMerkleFirstRound:      newMerkle(hints.SparkHints.evaluesSumcheck.firstRoundMerklePaths.path, true),
			EvaluesSumcheckMerkleRemainingRounds: newMerkle(hints.SparkHints.evaluesSumcheck.roundHints, true),

			ValsMerkleFirstRound:      newMerkle(hints.SparkHints.vals.firstRoundMerklePaths.path, true),
			ValsMerkleRemainingRounds: newMerkle(hints.SparkHints.vals.roundHints, true),

			RSWSMerkleFirstRound:      newMerkle(hints.SparkHints.rsws.firstRoundMerklePaths.path, true),
			RSWSMerkleRemainingRounds: newMerkle(hints.SparkHints.rsws.roundHints, true),

			EvaluesRSWSMerkleFirstRound:      newMerkle(hints.SparkHints.evaluesRSWS.firstRoundMerklePaths.path, true),
			EvaluesRSWSMerkleRemainingRounds: newMerkle(hints.SparkHints.evaluesRSWS.roundHints, true),

			RowFinalMerkleFirstRound:      newMerkle(hints.SparkHints.rowFinal.firstRoundMerklePaths.path, true),
			RowFinalMerkleRemainingRounds: newMerkle(hints.SparkHints.rowFinal.roundHints, true),

			ColFinalMerkleFirstRound:      newMerkle(hints.SparkHints.colFinal.firstRoundMerklePaths.path, true),
			ColFinalMerkleRemainingRounds: newMerkle(hints.SparkHints.colFinal.roundHints, true),

			WHIR2: NewWhirParams(sparkConfig.WHIR2),
			WHIR3: NewWhirParams(sparkConfig.WHIR3),
			WHIR4: NewWhirParams(sparkConfig.WHIR4),

			LogNumTerms: sparkConfig.LogNumTerms,
		},

		UseSpark: useSpark,
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
			if err := os.MkdirAll(buildOps.SaveKeys, 0755); err != nil {
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
		LogANumTerms:    sparkConfig.LogNumTerms,

		PointRow: pointRow,
		PointCol: pointCol,

		SparkRLC: SPARKMatrixData{
			Claimed: typeConverters.LimbsToBigIntMod(hints.SparkHints.claimed.Limbs),

			SparkSumcheckLast: sparkSumcheckLast,

			RowFinalCounter:          typeConverters.LimbsToBigIntMod(hints.SparkHints.rowFinalCounter.Limbs),
			RowRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.SparkHints.rowRSAddressEvaluation.Limbs),
			RowRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.SparkHints.rowRSValueEvaluation.Limbs),
			RowRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.SparkHints.rowRSTimestampEvaluation.Limbs),

			ColFinalCounter:          typeConverters.LimbsToBigIntMod(hints.SparkHints.colFinalCounter.Limbs),
			ColRSAddressEvaluation:   typeConverters.LimbsToBigIntMod(hints.SparkHints.colRSAddressEvaluation.Limbs),
			ColRSValueEvaluation:     typeConverters.LimbsToBigIntMod(hints.SparkHints.colRSValueEvaluation.Limbs),
			ColRSTimestampEvaluation: typeConverters.LimbsToBigIntMod(hints.SparkHints.colRSTimestampEvaluation.Limbs),

			EvaluesSumcheckMerkleFirstRound:      newMerkle(hints.SparkHints.evaluesSumcheck.firstRoundMerklePaths.path, false),
			EvaluesSumcheckMerkleRemainingRounds: newMerkle(hints.SparkHints.evaluesSumcheck.roundHints, false),

			ValsMerkleFirstRound:      newMerkle(hints.SparkHints.vals.firstRoundMerklePaths.path, false),
			ValsMerkleRemainingRounds: newMerkle(hints.SparkHints.vals.roundHints, false),

			RSWSMerkleFirstRound:      newMerkle(hints.SparkHints.rsws.firstRoundMerklePaths.path, false),
			RSWSMerkleRemainingRounds: newMerkle(hints.SparkHints.rsws.roundHints, false),

			EvaluesRSWSMerkleFirstRound:      newMerkle(hints.SparkHints.evaluesRSWS.firstRoundMerklePaths.path, false),
			EvaluesRSWSMerkleRemainingRounds: newMerkle(hints.SparkHints.evaluesRSWS.roundHints, false),

			RowFinalMerkleFirstRound:      newMerkle(hints.SparkHints.rowFinal.firstRoundMerklePaths.path, false),
			RowFinalMerkleRemainingRounds: newMerkle(hints.SparkHints.rowFinal.roundHints, false),

			ColFinalMerkleFirstRound:      newMerkle(hints.SparkHints.colFinal.firstRoundMerklePaths.path, false),
			ColFinalMerkleRemainingRounds: newMerkle(hints.SparkHints.colFinal.roundHints, false),

			WHIR2: NewWhirParams(sparkConfig.WHIR2),
			WHIR3: NewWhirParams(sparkConfig.WHIR3),
			WHIR4: NewWhirParams(sparkConfig.WHIR4),

			LogNumTerms: sparkConfig.LogNumTerms,
		},

		UseSpark: useSpark,
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

	gpaClaimedValues = []frontend.Variable{
		gpaClaimedValues[0],
		api.Add(gpaClaimedValues[0], gpaClaimedValues[1]),
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
	claimedEvaluations := make([]frontend.Variable, 3)
	if err := arthur.FillNextScalars(claimedEvaluations); err != nil {
		return err
	}

	matrixCombinationRandomness := make([]frontend.Variable, 1)
	if err := arthur.FillChallengeScalars(matrixCombinationRandomness); err != nil {
		return err
	}

	claimedValue := api.Add(
		claimedEvaluations[0],
		api.Mul(claimedEvaluations[1], matrixCombinationRandomness[0]),
		api.Mul(claimedEvaluations[2], matrixCombinationRandomness[0], matrixCombinationRandomness[0]),
	)

	valsCommitment, err := parseBatchedCommitment(arthur, matrix.WHIR3)
	if err != nil {
		return err
	}
	rsWSCommitment, err := parseBatchedCommitment(arthur, matrix.WHIR4)
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
	evaluesCommitment, err := parseBatchedCommitment(arthur, matrix.WHIR2)
	if err != nil {
		return err
	}

	sparkSumcheckFoldingRandomness, sparkSumcheckLastEval, err := runSumcheck(api, arthur, claimedValue, matrix.LogNumTerms, 4)
	if err != nil {
		return err
	}

	// Verify spark sumcheck last value

	claimedVal := api.Add(
		matrix.SparkSumcheckLast[0],
		api.Mul(matrix.SparkSumcheckLast[1], matrixCombinationRandomness[0]),
		api.Mul(matrix.SparkSumcheckLast[2], matrixCombinationRandomness[0], matrixCombinationRandomness[0]),
	)

	api.AssertIsEqual(sparkSumcheckLastEval, api.Mul(claimedVal, matrix.SparkSumcheckLast[3], matrix.SparkSumcheckLast[4]))

	_, err = RunZKWhir(api, arthur, uapi, sc, matrix.EvaluesSumcheckMerkleRemainingRounds, matrix.EvaluesSumcheckMerkleFirstRound, matrix.WHIR2, [][]frontend.Variable{{}, {}}, []frontend.Variable{}, evaluesCommitment,
		[][]frontend.Variable{{matrix.SparkSumcheckLast[3]}, {matrix.SparkSumcheckLast[4]}},
		[][]frontend.Variable{sparkSumcheckFoldingRandomness},
	)
	if err != nil {
		return err
	}

	_, err = RunZKWhir(api, arthur, uapi, sc, matrix.ValsMerkleRemainingRounds, matrix.ValsMerkleFirstRound, matrix.WHIR3, [][]frontend.Variable{{}, {}, {}}, []frontend.Variable{}, valsCommitment,
		[][]frontend.Variable{{matrix.SparkSumcheckLast[0]}, {matrix.SparkSumcheckLast[1]}, {matrix.SparkSumcheckLast[2]}},
		[][]frontend.Variable{sparkSumcheckFoldingRandomness},
	)
	if err != nil {
		return err
	}

	// RS WS
	tauGammaTemp := make([]frontend.Variable, 2)
	if err := arthur.FillChallengeScalars(tauGammaTemp); err != nil {
		return err
	}
	tau := tauGammaTemp[0]
	gamma := tauGammaTemp[1]

	gpaResultRSWS, err := gpaSumcheckVerifier4(api, arthur, matrix.LogNumTerms+3)
	if err != nil {
		return err
	}

	rsws_combination_randomness := gpaResultRSWS.randomness[0:2]
	rsws_evaluation_randomness := gpaResultRSWS.randomness[2:]

	claimedRowRS := gpaResultRSWS.claimedProducts[0]
	claimedRowWS := gpaResultRSWS.claimedProducts[1]
	claimedColRS := gpaResultRSWS.claimedProducts[2]
	claimedColWS := gpaResultRSWS.claimedProducts[3]

	_, err = RunZKWhir(api, arthur, uapi, sc, matrix.RSWSMerkleRemainingRounds, matrix.RSWSMerkleFirstRound, matrix.WHIR4, [][]frontend.Variable{{}}, []frontend.Variable{}, rsWSCommitment,
		[][]frontend.Variable{{matrix.RowRSAddressEvaluation}, {matrix.RowRSTimestampEvaluation}, {matrix.ColRSAddressEvaluation}, {matrix.ColRSTimestampEvaluation}},
		[][]frontend.Variable{rsws_evaluation_randomness},
	)
	if err != nil {
		return err
	}

	_, err = RunZKWhir(api, arthur, uapi, sc, matrix.EvaluesRSWSMerkleRemainingRounds, matrix.EvaluesRSWSMerkleFirstRound, matrix.WHIR2, [][]frontend.Variable{{}}, []frontend.Variable{}, evaluesCommitment,
		[][]frontend.Variable{{matrix.RowRSValueEvaluation}, {matrix.ColRSValueEvaluation}},
		[][]frontend.Variable{rsws_evaluation_randomness},
	)
	if err != nil {
		return err
	}

	row_rs_opening := api.Sub(api.Add(api.Mul(matrix.RowRSAddressEvaluation, gamma, gamma), api.Mul(matrix.RowRSValueEvaluation, gamma), matrix.RowRSTimestampEvaluation), tau)
	row_ws_opening := api.Sub(api.Add(api.Mul(matrix.RowRSAddressEvaluation, gamma, gamma), api.Mul(matrix.RowRSValueEvaluation, gamma), matrix.RowRSTimestampEvaluation, 1), tau)
	col_rs_opening := api.Sub(api.Add(api.Mul(matrix.ColRSAddressEvaluation, gamma, gamma), api.Mul(matrix.ColRSValueEvaluation, gamma), matrix.ColRSTimestampEvaluation), tau)
	col_ws_opening := api.Sub(api.Add(api.Mul(matrix.ColRSAddressEvaluation, gamma, gamma), api.Mul(matrix.ColRSValueEvaluation, gamma), matrix.ColRSTimestampEvaluation, 1), tau)

	evaluated_value := api.Add(
		api.Mul(
			row_rs_opening,
			api.Sub(1, rsws_combination_randomness[0]),
			api.Sub(1, rsws_combination_randomness[1]),
		),
		api.Mul(
			row_ws_opening,
			api.Sub(1, rsws_combination_randomness[0]),
			rsws_combination_randomness[1],
		),
		api.Mul(
			col_rs_opening,
			rsws_combination_randomness[0],
			api.Sub(1, rsws_combination_randomness[1]),
		),
		api.Mul(
			col_ws_opening,
			rsws_combination_randomness[0],
			rsws_combination_randomness[1],
		),
	)

	api.AssertIsEqual(evaluated_value, gpaResultRSWS.lastSumcheckValue)

	// Rowwise

	rowwiseGpaResult, err := gpaSumcheckVerifier(api, arthur, len(circuit.PointRow)+2)
	if err != nil {
		return err
	}

	rowwiseClaimedInit := rowwiseGpaResult.claimedProducts[0]
	rowwiseClaimedFinal := rowwiseGpaResult.claimedProducts[1]

	last_randomness := rowwiseGpaResult.randomness[0]
	evaluation_randomness := rowwiseGpaResult.randomness[1:]

	addr := CalculateAdr(api, evaluation_randomness)
	mem := calculateEQ(api, circuit.PointRow, evaluation_randomness)
	init_cntr := 0

	init_opening := api.Sub(api.Add(api.Mul(addr, gamma, gamma), api.Mul(mem, gamma), init_cntr), tau)

	_, err = RunZKWhir(api, arthur, uapi, sc, matrix.RowFinalMerkleRemainingRounds, matrix.RowFinalMerkleFirstRound, circuit.WHIRRow, [][]frontend.Variable{{}}, []frontend.Variable{}, rowFinalCommitment,
		[][]frontend.Variable{{matrix.RowFinalCounter}},
		[][]frontend.Variable{evaluation_randomness},
	)
	if err != nil {
		return err
	}

	final_opening := api.Sub(api.Add(api.Mul(addr, gamma, gamma), api.Mul(mem, gamma), matrix.RowFinalCounter), tau)

	rowwise_evaluated_value := api.Add(api.Mul(init_opening, api.Sub(1, last_randomness)), api.Mul(final_opening, last_randomness))

	api.AssertIsEqual(rowwiseGpaResult.lastSumcheckValue, rowwise_evaluated_value)

	// Colwise

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

	colwiseinit_opening := api.Sub(api.Add(api.Mul(colwiseaddr, gamma, gamma), api.Mul(colwisemem, gamma), colwiseinit_cntr), tau)

	_, err = RunZKWhir(api, arthur, uapi, sc, circuit.SparkRLC.ColFinalMerkleRemainingRounds, circuit.SparkRLC.ColFinalMerkleFirstRound, circuit.WHIRCol, [][]frontend.Variable{{}}, []frontend.Variable{}, colFinalCommitment,
		[][]frontend.Variable{{matrix.ColFinalCounter}},
		[][]frontend.Variable{colwiseEvaluation_randomness},
	)
	if err != nil {
		return err
	}

	colwisefinal_opening := api.Sub(api.Add(api.Mul(colwiseaddr, gamma, gamma), api.Mul(colwisemem, gamma), matrix.ColFinalCounter), tau)
	colwiseevaluated_value := api.Add(api.Mul(colwiseinit_opening, api.Sub(1, colwiseLast_randomness)), api.Mul(colwisefinal_opening, colwiseLast_randomness))
	api.AssertIsEqual(colwiseInitFinalGpaResult.lastSumcheckValue, colwiseevaluated_value)

	api.AssertIsEqual(api.Mul(rowwiseClaimedInit, claimedRowWS), api.Mul(claimedRowRS, rowwiseClaimedFinal))
	api.AssertIsEqual(api.Mul(colwiseClaimedInit, claimedColWS), api.Mul(claimedColRS, colwiseClaimedFinal))

	return nil
}

func gpaSumcheckVerifier4(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	layerCount int,
) (GPASumcheckResult, error) {
	l := make([]frontend.Variable, 2)
	r := make([]frontend.Variable, 1)
	gpaClaimedValues := make([]frontend.Variable, 4)
	prevRand := make([]frontend.Variable, 2)

	err := arthur.FillNextScalars(gpaClaimedValues)
	if err != nil {
		return GPASumcheckResult{}, err
	}
	err = arthur.FillChallengeScalars(prevRand)
	if err != nil {
		return GPASumcheckResult{}, err
	}
	lastEval := api.Add(
		gpaClaimedValues[0],
		api.Mul(gpaClaimedValues[1], prevRand[1]),
		api.Mul(gpaClaimedValues[2], prevRand[0]),
		api.Mul(gpaClaimedValues[3], prevRand[0], prevRand[1]),
	)

	var rand []frontend.Variable

	for i := 2; i < (layerCount - 1); i++ {
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

	gpaClaimedValues = []frontend.Variable{
		gpaClaimedValues[0],
		api.Add(gpaClaimedValues[0], gpaClaimedValues[1]),
		api.Add(gpaClaimedValues[0], gpaClaimedValues[2]),
		api.Add(gpaClaimedValues[0], gpaClaimedValues[1], gpaClaimedValues[2], gpaClaimedValues[3]),
	}

	return GPASumcheckResult{
		claimedProducts:   gpaClaimedValues,
		lastSumcheckValue: lastEval,
		randomness:        prevRand,
	}, nil
}
