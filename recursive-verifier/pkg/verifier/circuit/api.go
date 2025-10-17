package circuit

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/consensys/gnark/backend/groth16"
	arkSerialize "github.com/reilabs/go-ark-serialize"

	"reilabs/whir-verifier-circuit/internal/keys"
	"reilabs/whir-verifier-circuit/internal/storage"
	"reilabs/whir-verifier-circuit/pkg/verifier/transcript"
	"reilabs/whir-verifier-circuit/pkg/verifier/types"
)

// PrepareAndVerifyCircuit orchestrates transcript parsing and circuit verification.
func PrepareAndVerifyCircuit(
	config types.Config,
	sparkConfig types.SparkConfig,
	r1cs types.R1CS,
	pk *groth16.ProvingKey,
	vk *groth16.VerifyingKey,
	buildOps BuildOptions,
) error {
	whirData, err := transcript.ParseWHIR(config.IOPattern, config.Transcript)
	if err != nil {
		return fmt.Errorf("failed to parse WHIR transcript: %w", err)
	}
	config.Transcript = whirData.Truncated

	merklePaths := whirData.MerklePaths
	stirAnswers := whirData.StirAnswers
	deferred := whirData.Deferred
	claimedEvaluations := whirData.Claimed

	sparkData, err := transcript.ParseSpark(sparkConfig.IOPattern, sparkConfig.Transcript)
	if err != nil {
		return fmt.Errorf("failed to parse SPARK transcript: %w", err)
	}
	spSparkConfig := sparkConfig
	spSparkConfig.Transcript = sparkData.Truncated

	sparkMerklePaths := sparkData.MerklePaths
	sparkStirAnswers := sparkData.StirAnswers
	sparkClaimedEvaluations := sparkData.SparkClaimedEvaluations

	rowFinalCounter := sparkData.RowFinalCounter
	rowRSAddressEvaluation := sparkData.RowRSAddressEvaluation
	rowRSValueEvaluation := sparkData.RowRSValueEvaluation
	rowRSTimestampEvaluation := sparkData.RowRSTimestampEvaluation

	colFinalCounter := sparkData.ColFinalCounter
	colRSAddressEvaluation := sparkData.ColRSAddressEvaluation
	colRSValueEvaluation := sparkData.ColRSValueEvaluation
	colRSTimestampEvaluation := sparkData.ColRSTimestampEvaluation

	claimedA := sparkData.ClaimedA
	pointRow := sparkData.PointRow
	pointCol := sparkData.PointCol

	internerBytes, err := hex.DecodeString(r1cs.Interner.Values)
	if err != nil {
		return fmt.Errorf("failed to decode interner values: %w", err)
	}

	var interner types.Interner
	if _, err = arkSerialize.CanonicalDeserializeWithMode(bytes.NewReader(internerBytes), &interner, false, false); err != nil {
		return fmt.Errorf("failed to deserialize interner: %w", err)
	}

	hidingSpartanData := consumeWhirData(config.WHIRConfigHidingSpartan, &merklePaths, &stirAnswers)
	witnessData := consumeWhirData(config.WHIRConfigWitness, &merklePaths, &stirAnswers)

	sparkSumcheckData := consumeWhirData(sparkConfig.WHIR5, &sparkMerklePaths, &sparkStirAnswers)
	rowFinal := consumeWhirData(sparkConfig.WHIRRow, &sparkMerklePaths, &sparkStirAnswers)
	rowwiseSparkMerkle := consumeWhirData(sparkConfig.WHIR3, &sparkMerklePaths, &sparkStirAnswers)
	colFinal := consumeWhirData(sparkConfig.WHIRCol, &sparkMerklePaths, &sparkStirAnswers)
	colwiseSparkMerkle := consumeWhirData(sparkConfig.WHIR3, &sparkMerklePaths, &sparkStirAnswers)

	hints := types.Hints{
		PointRow: pointRow,
		PointCol: pointCol,

		WitnessHints:      witnessData,
		SpartanHidingHint: hidingSpartanData,

		AHints: types.SparkMatrixHints{
			Claimed:            claimedA,
			SparkSumcheckData:  sparkSumcheckData,
			RowFinalMerkle:     rowFinal,
			RowwiseSparkMerkle: rowwiseSparkMerkle,
			ColFinalMerkle:     colFinal,
			ColwiseSparkMerkle: colwiseSparkMerkle,

			SparkClaimedEvaluations: sparkClaimedEvaluations[0],

			RowFinalCounter:          rowFinalCounter[0],
			RowRSAddressEvaluation:   rowRSAddressEvaluation[0],
			RowRSValueEvaluation:     rowRSValueEvaluation[0],
			RowRSTimestampEvaluation: rowRSTimestampEvaluation[0],

			ColFinalCounter:          colFinalCounter[0],
			ColRSAddressEvaluation:   colRSAddressEvaluation[0],
			ColRSValueEvaluation:     colRSValueEvaluation[0],
			ColRSTimestampEvaluation: colRSTimestampEvaluation[0],
		},
	}

	if err = verifyCircuit(deferred, config, spSparkConfig, hints, pk, vk, claimedEvaluations, r1cs, interner, buildOps); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	return nil
}

// LoadKeys loads the proving and verifying keys from the supplied sources.
func LoadKeys(ctx context.Context, pkSource, vkSource string) (*groth16.ProvingKey, *groth16.VerifyingKey, error) {
	if pkSource == "" && vkSource == "" {
		return nil, nil, nil
	}

	provider := keys.NewCompositeProvider()
	pk, vk, err := provider.LoadBoth(ctx, pkSource, vkSource)
	if err != nil {
		return nil, nil, err
	}

	return &pk, &vk, nil
}

// LoadR1CSFromURL downloads the R1CS JSON from the given URL.
func LoadR1CSFromURL(ctx context.Context, url string) ([]byte, error) {
	data, err := storage.NewHTTPLoader().Load(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to download R1CS from %s: %w", url, err)
	}
	return data, nil
}

func consumeWhirData(
	cfg types.WHIRConfig,
	merklePaths *[]types.FullMultiPath[types.KeccakDigest],
	stirAnswers *[][][]types.Fp256,
) types.ZKHint {
	var hint types.ZKHint

	if len(*merklePaths) > 0 && len(*stirAnswers) > 0 {
		firstRoundMerklePath := consumeFront(merklePaths)
		firstRoundStirAnswers := consumeFront(stirAnswers)

		hint.FirstRoundMerklePaths = types.FirstRoundHint{
			Path: types.Hint{
				MerklePaths: []types.FullMultiPath[types.KeccakDigest]{firstRoundMerklePath},
				StirAnswers: [][][]types.Fp256{firstRoundStirAnswers},
			},
			ExpectedStirAnswers: firstRoundStirAnswers,
		}
	}

	expectedRounds := cfg.NRounds
	remainingMerklePaths := make([]types.FullMultiPath[types.KeccakDigest], 0, expectedRounds)
	remainingStirAnswers := make([][][]types.Fp256, 0, expectedRounds)

	for i := 0; i < expectedRounds && len(*merklePaths) > 0 && len(*stirAnswers) > 0; i++ {
		remainingMerklePaths = append(remainingMerklePaths, consumeFront(merklePaths))
		remainingStirAnswers = append(remainingStirAnswers, consumeFront(stirAnswers))
	}

	hint.RoundHints = types.Hint{
		MerklePaths: remainingMerklePaths,
		StirAnswers: remainingStirAnswers,
	}

	return hint
}

func consumeFront[T any](slice *[]T) T {
	var zero T
	if len(*slice) == 0 {
		return zero
	}
	head := (*slice)[0]
	*slice = (*slice)[1:]
	return head
}
