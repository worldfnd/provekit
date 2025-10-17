package transcript

import (
	"bytes"
	"encoding/binary"
	"fmt"

	gnarkNimue "github.com/reilabs/gnark-nimue"
	arkSerialize "github.com/reilabs/go-ark-serialize"

	"reilabs/whir-verifier-circuit/pkg/verifier/types"
)

// WHIRParseResult captures data extracted from a WHIR transcript.
type WHIRParseResult struct {
	MerklePaths []types.FullMultiPath[types.KeccakDigest]
	StirAnswers [][][]types.Fp256
	Deferred    []types.Fp256
	Claimed     types.ClaimedEvaluations
	Truncated   []byte
}

// SparkParseResult captures data extracted from a SPARK transcript.
type SparkParseResult struct {
	MerklePaths             []types.FullMultiPath[types.KeccakDigest]
	StirAnswers             [][][]types.Fp256
	SparkClaimedEvaluations [][]types.Fp256

	RowFinalCounter          []types.Fp256
	RowRSAddressEvaluation   []types.Fp256
	RowRSValueEvaluation     []types.Fp256
	RowRSTimestampEvaluation []types.Fp256

	ColFinalCounter          []types.Fp256
	ColRSAddressEvaluation   []types.Fp256
	ColRSValueEvaluation     []types.Fp256
	ColRSTimestampEvaluation []types.Fp256

	ClaimedA types.Fp256
	ClaimedB types.Fp256
	ClaimedC types.Fp256
	PointRow []types.Fp256
	PointCol []types.Fp256

	Truncated []byte
}

// ParseWHIR consumes a WHIR transcript and returns the extracted hints.
func ParseWHIR(ioPattern string, transcript []byte) (WHIRParseResult, error) {
	pattern := gnarkNimue.IOPattern{}
	if err := pattern.Parse([]byte(ioPattern)); err != nil {
		return WHIRParseResult{}, fmt.Errorf("failed to parse IO pattern: %w", err)
	}

	var pointer uint64
	var truncated []byte

	var merklePaths []types.FullMultiPath[types.KeccakDigest]
	var stirAnswers [][][]types.Fp256
	var deferred []types.Fp256
	var claimed types.ClaimedEvaluations

	for _, op := range pattern.Ops {
		switch op.Kind {
		case gnarkNimue.Hint:
			if pointer+4 > uint64(len(transcript)) {
				return WHIRParseResult{}, fmt.Errorf("insufficient bytes for hint length")
			}
			hintLen := binary.LittleEndian.Uint32(transcript[pointer : pointer+4])
			start := pointer + 4
			end := start + uint64(hintLen)

			if end > uint64(len(transcript)) {
				return WHIRParseResult{}, fmt.Errorf("insufficient bytes for hint payload")
			}

			var err error
			switch string(op.Label) {
			case "merkle_proof":
				var path types.FullMultiPath[types.KeccakDigest]
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&path,
					false,
					false,
				)
				merklePaths = append(merklePaths, path)
			case "stir_answers":
				var answers [][]types.Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&answers,
					false,
					false,
				)
				stirAnswers = append(stirAnswers, answers)
			case "deferred_weight_evaluations":
				var block []types.Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&block,
					false,
					false,
				)
				if err != nil {
					return WHIRParseResult{}, fmt.Errorf("failed to deserialize deferred hint: %w", err)
				}
				deferred = append(deferred, block...)
			case "claimed_evaluations":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&claimed,
					false,
					false,
				)
				if err != nil {
					return WHIRParseResult{}, fmt.Errorf("failed to deserialize claimed_evaluations: %w", err)
				}
			}

			if err != nil {
				return WHIRParseResult{}, fmt.Errorf("failed to deserialize WHIR hint: %w", err)
			}

			pointer = end
		case gnarkNimue.Absorb:
			start := pointer
			if string(op.Label) == "pow-nonce" {
				pointer += op.Size
			} else {
				pointer += op.Size * 32
			}

			if pointer > uint64(len(transcript)) {
				return WHIRParseResult{}, fmt.Errorf("absorb exceeds transcript length")
			}

			truncated = append(truncated, transcript[start:pointer]...)
		}
	}

	return WHIRParseResult{
		MerklePaths: merklePaths,
		StirAnswers: stirAnswers,
		Deferred:    deferred,
		Claimed:     claimed,
		Truncated:   truncated,
	}, nil
}

// ParseSpark consumes a SPARK transcript and returns the extracted hints.
func ParseSpark(ioPattern string, transcript []byte) (SparkParseResult, error) {
	pattern := gnarkNimue.IOPattern{}
	if err := pattern.Parse([]byte(ioPattern)); err != nil {
		return SparkParseResult{}, fmt.Errorf("failed to parse IO pattern: %w", err)
	}

	var pointer uint64
	var truncated []byte

	var merklePaths []types.FullMultiPath[types.KeccakDigest]
	var stirAnswers [][][]types.Fp256
	var sparkClaimedEvaluations [][]types.Fp256

	var rowFinalCounter []types.Fp256
	var rowRSAddressEvaluation []types.Fp256
	var rowRSValueEvaluation []types.Fp256
	var rowRSTimestampEvaluation []types.Fp256

	var colFinalCounter []types.Fp256
	var colRSAddressEvaluation []types.Fp256
	var colRSValueEvaluation []types.Fp256
	var colRSTimestampEvaluation []types.Fp256

	var claimedA types.Fp256
	var claimedB types.Fp256
	var claimedC types.Fp256
	var pointRow []types.Fp256
	var pointCol []types.Fp256

	for _, op := range pattern.Ops {
		switch op.Kind {
		case gnarkNimue.Hint:
			if pointer+4 > uint64(len(transcript)) {
				return SparkParseResult{}, fmt.Errorf("insufficient bytes for hint length")
			}
			hintLen := binary.LittleEndian.Uint32(transcript[pointer : pointer+4])
			start := pointer + 4
			end := start + uint64(hintLen)

			if end > uint64(len(transcript)) {
				return SparkParseResult{}, fmt.Errorf("insufficient bytes for hint payload")
			}

			var err error
			switch string(op.Label) {
			case "merkle_proof":
				var path types.FullMultiPath[types.KeccakDigest]
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&path,
					false,
					false,
				)
				merklePaths = append(merklePaths, path)
			case "stir_answers":
				var answers [][]types.Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&answers,
					false,
					false,
				)
				stirAnswers = append(stirAnswers, answers)
			case "sumcheck_last_folds":
				var folds []types.Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&folds,
					false,
					false,
				)
				if err != nil {
					return SparkParseResult{}, fmt.Errorf("failed to deserialize spark_last_folds: %w", err)
				}
				sparkClaimedEvaluations = append(sparkClaimedEvaluations, folds)
			case "row_final_counter_claimed_evaluation":
				var value types.Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&value,
					false,
					false,
				)
				if err != nil {
					return SparkParseResult{}, fmt.Errorf("failed to deserialize row_final_counter_claimed_evaluation: %w", err)
				}
				rowFinalCounter = append(rowFinalCounter, value)
			case "row_rs_address_claimed_evaluation":
				var value types.Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&value,
					false,
					false,
				)
				if err != nil {
					return SparkParseResult{}, fmt.Errorf("failed to deserialize row_rs_address_claimed_evaluation: %w", err)
				}
				rowRSAddressEvaluation = append(rowRSAddressEvaluation, value)
			case "row_rs_value_claimed_evaluation":
				var value types.Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&value,
					false,
					false,
				)
				if err != nil {
					return SparkParseResult{}, fmt.Errorf("failed to deserialize row_rs_value_claimed_evaluation: %w", err)
				}
				rowRSValueEvaluation = append(rowRSValueEvaluation, value)
			case "row_rs_timestamp_claimed_evaluation":
				var value types.Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&value,
					false,
					false,
				)
				if err != nil {
					return SparkParseResult{}, fmt.Errorf("failed to deserialize row_rs_timestamp_claimed_evaluation: %w", err)
				}
				rowRSTimestampEvaluation = append(rowRSTimestampEvaluation, value)
			case "col_final_counter_claimed_evaluation":
				var value types.Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&value,
					false,
					false,
				)
				if err != nil {
					return SparkParseResult{}, fmt.Errorf("failed to deserialize col_final_counter_claimed_evaluation: %w", err)
				}
				colFinalCounter = append(colFinalCounter, value)
			case "col_rs_address_claimed_evaluation":
				var value types.Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&value,
					false,
					false,
				)
				if err != nil {
					return SparkParseResult{}, fmt.Errorf("failed to deserialize col_rs_address_claimed_evaluation: %w", err)
				}
				colRSAddressEvaluation = append(colRSAddressEvaluation, value)
			case "col_rs_value_claimed_evaluation":
				var value types.Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&value,
					false,
					false,
				)
				if err != nil {
					return SparkParseResult{}, fmt.Errorf("failed to deserialize col_rs_value_claimed_evaluation: %w", err)
				}
				colRSValueEvaluation = append(colRSValueEvaluation, value)
			case "col_rs_timestamp_claimed_evaluation":
				var value types.Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&value,
					false,
					false,
				)
				if err != nil {
					return SparkParseResult{}, fmt.Errorf("failed to deserialize col_rs_timestamp_claimed_evaluation: %w", err)
				}
				colRSTimestampEvaluation = append(colRSTimestampEvaluation, value)
			case "claimed_a":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&claimedA,
					false,
					false,
				)
				if err != nil {
					return SparkParseResult{}, fmt.Errorf("failed to deserialize claimed_a: %w", err)
				}
			case "claimed_b":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&claimedB,
					false,
					false,
				)
				if err != nil {
					return SparkParseResult{}, fmt.Errorf("failed to deserialize claimed_b: %w", err)
				}
			case "claimed_c":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&claimedC,
					false,
					false,
				)
				if err != nil {
					return SparkParseResult{}, fmt.Errorf("failed to deserialize claimed_c: %w", err)
				}
			case "point_row":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&pointRow,
					false,
					false,
				)
				if err != nil {
					return SparkParseResult{}, fmt.Errorf("failed to deserialize point_row: %w", err)
				}
			case "point_col":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(transcript[start:end]),
					&pointCol,
					false,
					false,
				)
				if err != nil {
					return SparkParseResult{}, fmt.Errorf("failed to deserialize point_col: %w", err)
				}
			}

			if err != nil {
				return SparkParseResult{}, fmt.Errorf("failed to deserialize SPARK hint: %w", err)
			}

			pointer = end
		case gnarkNimue.Absorb:
			start := pointer
			if string(op.Label) == "pow-nonce" {
				pointer += op.Size
			} else {
				pointer += op.Size * 32
			}

			if pointer > uint64(len(transcript)) {
				return SparkParseResult{}, fmt.Errorf("absorb exceeds transcript length")
			}

			truncated = append(truncated, transcript[start:pointer]...)
		}
	}

	return SparkParseResult{
		MerklePaths:              merklePaths,
		StirAnswers:              stirAnswers,
		SparkClaimedEvaluations:  sparkClaimedEvaluations,
		RowFinalCounter:          rowFinalCounter,
		RowRSAddressEvaluation:   rowRSAddressEvaluation,
		RowRSValueEvaluation:     rowRSValueEvaluation,
		RowRSTimestampEvaluation: rowRSTimestampEvaluation,
		ColFinalCounter:          colFinalCounter,
		ColRSAddressEvaluation:   colRSAddressEvaluation,
		ColRSValueEvaluation:     colRSValueEvaluation,
		ColRSTimestampEvaluation: colRSTimestampEvaluation,
		ClaimedA:                 claimedA,
		ClaimedB:                 claimedB,
		ClaimedC:                 claimedC,
		PointRow:                 pointRow,
		PointCol:                 pointCol,
		Truncated:                truncated,
	}, nil
}
