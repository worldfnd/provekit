package circuit

import (
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"

	"reilabs/whir-verifier-circuit/pkg/encoding/typeconv"
	"reilabs/whir-verifier-circuit/pkg/verifier/merkle"
	"reilabs/whir-verifier-circuit/pkg/verifier/types"
	"reilabs/whir-verifier-circuit/pkg/verifier/whir"
)

func verifyCircuit(
	deferred []types.Fp256,
	cfg types.Config,
	sparkConfig types.SparkConfig,
	hints types.Hints,
	pk *groth16.ProvingKey,
	vk *groth16.VerifyingKey,
	claimedEvaluations types.ClaimedEvaluations,
	internedR1CS types.R1CS,
	interner types.Interner,
	buildOps BuildOptions,
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

	hidingSpartanLinearStatementEvaluations[0] = typeconv.LimbsToBigIntMod(deferred[0].Limbs)
	witnessLinearStatementEvaluations[0] = typeconv.LimbsToBigIntMod(deferred[1].Limbs)
	witnessLinearStatementEvaluations[1] = typeconv.LimbsToBigIntMod(deferred[2].Limbs)
	witnessLinearStatementEvaluations[2] = typeconv.LimbsToBigIntMod(deferred[3].Limbs)

	contSparkSumcheckLast := make([]frontend.Variable, 5)
	sparkSumcheckLast := make([]frontend.Variable, 5)
	sparkSumcheckLast[0] = typeconv.LimbsToBigIntMod(hints.AHints.SparkClaimedEvaluations[0].Limbs)
	sparkSumcheckLast[1] = typeconv.LimbsToBigIntMod(hints.AHints.SparkClaimedEvaluations[1].Limbs)
	sparkSumcheckLast[2] = typeconv.LimbsToBigIntMod(hints.AHints.SparkClaimedEvaluations[2].Limbs)
	sparkSumcheckLast[3] = typeconv.LimbsToBigIntMod(hints.AHints.SparkClaimedEvaluations[3].Limbs)
	sparkSumcheckLast[4] = typeconv.LimbsToBigIntMod(hints.AHints.SparkClaimedEvaluations[4].Limbs)

	contPointRow := make([]frontend.Variable, len(hints.PointRow))
	pointRow := make([]frontend.Variable, len(hints.PointRow))
	for i := range hints.PointRow {
		pointRow[i] = typeconv.LimbsToBigIntMod(hints.PointRow[i].Limbs)
	}

	contPointCol := make([]frontend.Variable, len(hints.PointCol))
	pointCol := make([]frontend.Variable, len(hints.PointCol))
	for i := range hints.PointCol {
		pointCol[i] = typeconv.LimbsToBigIntMod(hints.PointCol[i].Limbs)
	}

	fSums, gSums := parseClaimedEvaluations(claimedEvaluations, true)

	matrixA := make([]types.MatrixCell, len(internedR1CS.A.Values))
	for i := range internedR1CS.A.RowIndices {
		end := len(internedR1CS.A.Values) - 1
		if i < len(internedR1CS.A.RowIndices)-1 {
			end = int(internedR1CS.A.RowIndices[i+1] - 1)
		}
		for j := int(internedR1CS.A.RowIndices[i]); j <= end; j++ {
			matrixA[j] = types.MatrixCell{
				Row:    i,
				Column: int(internedR1CS.A.ColIndices[j]),
				Value:  typeconv.LimbsToBigIntMod(interner.Values[internedR1CS.A.Values[j]].Limbs),
			}
		}
	}

	matrixB := make([]types.MatrixCell, len(internedR1CS.B.Values))
	for i := range internedR1CS.B.RowIndices {
		end := len(internedR1CS.B.Values) - 1
		if i < len(internedR1CS.B.RowIndices)-1 {
			end = int(internedR1CS.B.RowIndices[i+1] - 1)
		}
		for j := int(internedR1CS.B.RowIndices[i]); j <= end; j++ {
			matrixB[j] = types.MatrixCell{
				Row:    i,
				Column: int(internedR1CS.B.ColIndices[j]),
				Value:  typeconv.LimbsToBigIntMod(interner.Values[internedR1CS.B.Values[j]].Limbs),
			}
		}
	}

	matrixC := make([]types.MatrixCell, len(internedR1CS.C.Values))
	for i := range internedR1CS.C.RowIndices {
		end := len(internedR1CS.C.Values) - 1
		if i < len(internedR1CS.C.RowIndices)-1 {
			end = int(internedR1CS.C.RowIndices[i+1] - 1)
		}
		for j := int(internedR1CS.C.RowIndices[i]); j <= end; j++ {
			matrixC[j] = types.MatrixCell{
				Row:    i,
				Column: int(internedR1CS.C.ColIndices[j]),
				Value:  typeconv.LimbsToBigIntMod(interner.Values[internedR1CS.C.Values[j]].Limbs),
			}
		}
	}

	useSpark := buildOps.Evaluation == "spark"

	circuit := Circuit{
		IO:                                      []byte(cfg.IOPattern),
		Transcript:                              contTranscript,
		LogNumConstraints:                       cfg.LogNumConstraints,
		WitnessClaimedEvaluations:               fSums,
		WitnessBlindingEvaluations:              gSums,
		WitnessLinearStatementEvaluations:       contWitnessLinearStatementEvaluations,
		HidingSpartanLinearStatementEvaluations: contHidingSpartanLinearStatementEvaluations,
		HidingSpartanFirstRound:                 merkle.New(hints.SpartanHidingHint.FirstRoundMerklePaths.Path, true),
		HidingSpartanMerkle:                     merkle.New(hints.SpartanHidingHint.RoundHints, true),
		WitnessMerkle:                           merkle.New(hints.WitnessHints.RoundHints, true),
		WitnessFirstRound:                       merkle.New(hints.WitnessHints.FirstRoundMerklePaths.Path, true),

		WHIRParamsWitness:       whir.NewParams(cfg.WHIRConfigWitness),
		WHIRParamsHidingSpartan: whir.NewParams(cfg.WHIRConfigHidingSpartan),

		MatrixA: matrixA,
		MatrixB: matrixB,
		MatrixC: matrixC,

		SPARKIO:         []byte(sparkConfig.IOPattern),
		SPARKTranscript: sparkContTranscript,
		WHIRRow:         whir.NewParams(sparkConfig.WHIRRow),
		WHIRCol:         whir.NewParams(sparkConfig.WHIRCol),

		LogANumTerms: sparkConfig.LogNumTerms,

		PointRow: contPointRow,
		PointCol: contPointCol,

		SparkRLC: types.SPARKMatrixData{
			Claimed: typeconv.LimbsToBigIntMod(hints.AHints.Claimed.Limbs),

			SparkSumcheckLast: contSparkSumcheckLast,

			RowFinalCounter:          typeconv.LimbsToBigIntMod(hints.AHints.RowFinalCounter.Limbs),
			RowRSAddressEvaluation:   typeconv.LimbsToBigIntMod(hints.AHints.RowRSAddressEvaluation.Limbs),
			RowRSValueEvaluation:     typeconv.LimbsToBigIntMod(hints.AHints.RowRSValueEvaluation.Limbs),
			RowRSTimestampEvaluation: typeconv.LimbsToBigIntMod(hints.AHints.RowRSTimestampEvaluation.Limbs),

			ColFinalCounter:          typeconv.LimbsToBigIntMod(hints.AHints.ColFinalCounter.Limbs),
			ColRSAddressEvaluation:   typeconv.LimbsToBigIntMod(hints.AHints.ColRSAddressEvaluation.Limbs),
			ColRSValueEvaluation:     typeconv.LimbsToBigIntMod(hints.AHints.ColRSValueEvaluation.Limbs),
			ColRSTimestampEvaluation: typeconv.LimbsToBigIntMod(hints.AHints.ColRSTimestampEvaluation.Limbs),

			SparkSumcheckFirstRound: merkle.New(hints.AHints.SparkSumcheckData.FirstRoundMerklePaths.Path, true),
			SparkSumcheckMerkle:     merkle.New(hints.AHints.SparkSumcheckData.RoundHints, true),

			RowFinalMerkleFirstRound: merkle.New(hints.AHints.RowFinalMerkle.FirstRoundMerklePaths.Path, true),
			RowFinalMerkle:           merkle.New(hints.AHints.RowFinalMerkle.RoundHints, true),

			RowwiseMerkleFirstRound: merkle.New(hints.AHints.RowwiseSparkMerkle.FirstRoundMerklePaths.Path, true),
			RowwiseMerkle:           merkle.New(hints.AHints.RowwiseSparkMerkle.RoundHints, true),

			ColFinalMerkleFirstRound: merkle.New(hints.AHints.ColFinalMerkle.FirstRoundMerklePaths.Path, true),
			ColFinalMerkle:           merkle.New(hints.AHints.ColFinalMerkle.RoundHints, true),

			ColwiseMerkleFirstRound: merkle.New(hints.AHints.ColwiseSparkMerkle.FirstRoundMerklePaths.Path, true),
			ColwiseMerkle:           merkle.New(hints.AHints.ColwiseSparkMerkle.RoundHints, true),

			WHIR3: whir.NewParams(sparkConfig.WHIR3),
			WHIR5: whir.NewParams(sparkConfig.WHIR5),

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
				_, err = (*pk).WriteTo(pkFile)
				if err != nil {
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
				_, err = (*vk).WriteTo(vkFile)
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

		HidingSpartanFirstRound: merkle.New(hints.SpartanHidingHint.FirstRoundMerklePaths.Path, false),
		HidingSpartanMerkle:     merkle.New(hints.SpartanHidingHint.RoundHints, false),
		WitnessMerkle:           merkle.New(hints.WitnessHints.RoundHints, false),
		WitnessFirstRound:       merkle.New(hints.WitnessHints.FirstRoundMerklePaths.Path, false),

		WHIRParamsWitness:       whir.NewParams(cfg.WHIRConfigWitness),
		WHIRParamsHidingSpartan: whir.NewParams(cfg.WHIRConfigHidingSpartan),

		MatrixA: matrixA,
		MatrixB: matrixB,
		MatrixC: matrixC,

		SPARKIO:         []byte(sparkConfig.IOPattern),
		SPARKTranscript: sparkTranscriptT,
		WHIRRow:         whir.NewParams(sparkConfig.WHIRRow),
		WHIRCol:         whir.NewParams(sparkConfig.WHIRCol),
		LogANumTerms:    sparkConfig.LogNumTerms,

		PointRow: pointRow,
		PointCol: pointCol,

		SparkRLC: types.SPARKMatrixData{
			Claimed: typeconv.LimbsToBigIntMod(hints.AHints.Claimed.Limbs),

			SparkSumcheckLast: sparkSumcheckLast,

			RowFinalCounter:          typeconv.LimbsToBigIntMod(hints.AHints.RowFinalCounter.Limbs),
			RowRSAddressEvaluation:   typeconv.LimbsToBigIntMod(hints.AHints.RowRSAddressEvaluation.Limbs),
			RowRSValueEvaluation:     typeconv.LimbsToBigIntMod(hints.AHints.RowRSValueEvaluation.Limbs),
			RowRSTimestampEvaluation: typeconv.LimbsToBigIntMod(hints.AHints.RowRSTimestampEvaluation.Limbs),

			ColFinalCounter:          typeconv.LimbsToBigIntMod(hints.AHints.ColFinalCounter.Limbs),
			ColRSAddressEvaluation:   typeconv.LimbsToBigIntMod(hints.AHints.ColRSAddressEvaluation.Limbs),
			ColRSValueEvaluation:     typeconv.LimbsToBigIntMod(hints.AHints.ColRSValueEvaluation.Limbs),
			ColRSTimestampEvaluation: typeconv.LimbsToBigIntMod(hints.AHints.ColRSTimestampEvaluation.Limbs),

			SparkSumcheckFirstRound: merkle.New(hints.AHints.SparkSumcheckData.FirstRoundMerklePaths.Path, false),
			SparkSumcheckMerkle:     merkle.New(hints.AHints.SparkSumcheckData.RoundHints, false),

			RowFinalMerkleFirstRound: merkle.New(hints.AHints.RowFinalMerkle.FirstRoundMerklePaths.Path, false),
			RowFinalMerkle:           merkle.New(hints.AHints.RowFinalMerkle.RoundHints, false),

			RowwiseMerkleFirstRound: merkle.New(hints.AHints.RowwiseSparkMerkle.FirstRoundMerklePaths.Path, false),
			RowwiseMerkle:           merkle.New(hints.AHints.RowwiseSparkMerkle.RoundHints, false),

			ColFinalMerkleFirstRound: merkle.New(hints.AHints.ColFinalMerkle.FirstRoundMerklePaths.Path, false),
			ColFinalMerkle:           merkle.New(hints.AHints.ColFinalMerkle.RoundHints, false),

			ColwiseMerkleFirstRound: merkle.New(hints.AHints.ColwiseSparkMerkle.FirstRoundMerklePaths.Path, false),
			ColwiseMerkle:           merkle.New(hints.AHints.ColwiseSparkMerkle.RoundHints, false),

			WHIR3: whir.NewParams(sparkConfig.WHIR3),
			WHIR5: whir.NewParams(sparkConfig.WHIR5),

			LogNumTerms: sparkConfig.LogNumTerms,
		},

		UseSpark: useSpark,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	opts := []backend.ProverOption{
		backend.WithSolverOptions(solver.WithHints(indexOfHint)),
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

func indexOfHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(outputs) != 1 {
		return fmt.Errorf("expecting one output")
	}
	if len(inputs) == 0 {
		return fmt.Errorf("inputs array cannot be empty")
	}

	target := inputs[0]
	for i := 1; i < len(inputs); i++ {
		if inputs[i].Cmp(target) == 0 {
			outputs[0] = big.NewInt(int64(i - 1))
			return nil
		}
	}

	outputs[0] = big.NewInt(-1)
	return nil
}
