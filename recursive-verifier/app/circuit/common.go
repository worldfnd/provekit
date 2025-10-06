package circuit

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/consensys/gnark/backend/groth16"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	arkSerialize "github.com/reilabs/go-ark-serialize"

	"reilabs/whir-verifier-circuit/app/common"
)

func PrepareAndVerifyCircuit(config Config, sparkConfig SparkConfig, r1cs R1CS, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, buildOps common.BuildOps) error {
	io := gnarkNimue.IOPattern{}
	err := io.Parse([]byte(config.IOPattern))
	if err != nil {
		return fmt.Errorf("failed to parse IO pattern: %w", err)
	}

	var pointer uint64
	var truncated []byte

	var merklePaths []FullMultiPath[KeccakDigest]
	var stirAnswers [][][]Fp256
	var deferred []Fp256
	var claimedEvaluations ClaimedEvaluations

	for _, op := range io.Ops {
		switch op.Kind {
		case gnarkNimue.Hint:
			if pointer+4 > uint64(len(config.Transcript)) {
				return fmt.Errorf("insufficient bytes for hint length")
			}
			hintLen := binary.LittleEndian.Uint32(config.Transcript[pointer : pointer+4])
			start := pointer + 4
			end := start + uint64(hintLen)

			if end > uint64(len(config.Transcript)) {
				return fmt.Errorf("insufficient bytes for merkle proof")
			}

			switch string(op.Label) {
			case "merkle_proof":
				var path FullMultiPath[KeccakDigest]
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&path,
					false, false,
				)
				merklePaths = append(merklePaths, path)

			case "stir_answers":
				var stirAnswersTemporary [][]Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&stirAnswersTemporary,
					false, false,
				)
				stirAnswers = append(stirAnswers, stirAnswersTemporary)

			case "deferred_weight_evaluations":
				var deferredTemporary []Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&deferredTemporary,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize deferred hint: %w", err)
				}
				deferred = append(deferred, deferredTemporary...)
			case "claimed_evaluations":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&claimedEvaluations,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize claimed_evaluations: %w", err)
				}
			}

			if err != nil {
				return fmt.Errorf("failed to deserialize merkle proof: %w", err)
			}

			pointer = end

		case gnarkNimue.Absorb:
			start := pointer
			if string(op.Label) == "pow-nonce" {
				pointer += op.Size
			} else {
				pointer += op.Size * 32
			}

			if pointer > uint64(len(config.Transcript)) {
				return fmt.Errorf("absorb exceeds transcript length")
			}

			truncated = append(truncated, config.Transcript[start:pointer]...)
		}
	}

	config.Transcript = truncated

	// Spark start
	spark_io := gnarkNimue.IOPattern{}
	err = spark_io.Parse([]byte(sparkConfig.IOPattern))
	if err != nil {
		return fmt.Errorf("failed to parse IO pattern: %w", err)
	}

	var spark_pointer uint64
	var spark_truncated_transcript []byte

	var sparkMerklePaths []FullMultiPath[KeccakDigest]
	var sparkStirAnswers [][][]Fp256
	var sparkClaimedEvaluations [][]Fp256

	var rowFinalCounter []Fp256
	var rowRSAddressEvaluation []Fp256
	var rowRSValueEvaluation []Fp256
	var rowRSTimestampEvaluation []Fp256

	var colFinalCounter []Fp256
	var colRSAddressEvaluation []Fp256
	var colRSValueEvaluation []Fp256
	var colRSTimestampEvaluation []Fp256

	var claimedA Fp256
	var claimedB Fp256
	var claimedC Fp256
	var pointRow []Fp256
	var pointCol []Fp256

	for _, op := range spark_io.Ops {
		switch op.Kind {
		case gnarkNimue.Hint:
			if spark_pointer+4 > uint64(len(sparkConfig.Transcript)) {
				return fmt.Errorf("insufficient bytes for hint length")
			}
			hintLen := binary.LittleEndian.Uint32(sparkConfig.Transcript[spark_pointer : spark_pointer+4])
			start := spark_pointer + 4
			end := start + uint64(hintLen)

			if end > uint64(len(sparkConfig.Transcript)) {
				return fmt.Errorf("insufficient bytes for merkle proof")
			}

			switch string(op.Label) {
			case "merkle_proof":
				var path FullMultiPath[KeccakDigest]
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&path,
					false, false,
				)
				sparkMerklePaths = append(sparkMerklePaths, path)

			case "stir_answers":
				var stirAnswersTemporary [][]Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&stirAnswersTemporary,
					false, false,
				)
				sparkStirAnswers = append(sparkStirAnswers, stirAnswersTemporary)
			case "sumcheck_last_folds":
				var temp []Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&temp,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize spark_last_folds: %w", err)
				}
				sparkClaimedEvaluations = append(sparkClaimedEvaluations, temp)
			case "row_final_counter_claimed_evaluation":
				var temp Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&temp,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize row_final_counter_claimed_evaluation : %w", err)
				}
				rowFinalCounter = append(rowFinalCounter, temp)
			case "row_rs_address_claimed_evaluation":
				var temp Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&temp,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize row_rs_address_claimed_evaluation : %w", err)
				}
				rowRSAddressEvaluation = append(rowRSAddressEvaluation, temp)
			case "row_rs_value_claimed_evaluation":
				var temp Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&temp,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize row_rs_value_claimed_evaluation : %w", err)
				}
				rowRSValueEvaluation = append(rowRSValueEvaluation, temp)
			case "row_rs_timestamp_claimed_evaluation":
				var temp Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&temp,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize row_rs_timestamp_claimed_evaluation : %w", err)
				}
				rowRSTimestampEvaluation = append(rowRSTimestampEvaluation, temp)
			case "col_final_counter_claimed_evaluation":
				var temp Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&temp,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize col_final_counter_claimed_evaluation : %w", err)
				}
				colFinalCounter = append(colFinalCounter, temp)
			case "col_rs_address_claimed_evaluation":
				var temp Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&temp,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize col_rs_address_claimed_evaluation : %w", err)
				}
				colRSAddressEvaluation = append(colRSAddressEvaluation, temp)
			case "col_rs_value_claimed_evaluation":
				var temp Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&temp,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize col_rs_value_claimed_evaluation : %w", err)
				}
				colRSValueEvaluation = append(colRSValueEvaluation, temp)
			case "col_rs_timestamp_claimed_evaluation":
				var temp Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&temp,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize col_rs_timestamp_claimed_evaluation : %w", err)
				}
				colRSTimestampEvaluation = append(colRSTimestampEvaluation, temp)
			case "claimed_a":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&claimedA,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize row_rs_address_claimed_evaluation : %w", err)
				}
			case "claimed_b":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&claimedB,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize row_rs_address_claimed_evaluation : %w", err)
				}
			case "claimed_c":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&claimedC,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize row_rs_address_claimed_evaluation : %w", err)
				}
			case "point_row":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&pointRow,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize row_rs_address_claimed_evaluation : %w", err)
				}
			case "point_col":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(sparkConfig.Transcript[start:end]),
					&pointCol,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize row_rs_address_claimed_evaluation : %w", err)
				}
			}

			if err != nil {
				return fmt.Errorf("failed to deserialize merkle proof: %w", err)
			}

			spark_pointer = end

		case gnarkNimue.Absorb:
			start := spark_pointer
			if string(op.Label) == "pow-nonce" {
				spark_pointer += op.Size
			} else {
				spark_pointer += op.Size * 32
			}

			if spark_pointer > uint64(len(sparkConfig.Transcript)) {
				return fmt.Errorf("absorb exceeds transcript length")
			}

			spark_truncated_transcript = append(spark_truncated_transcript, sparkConfig.Transcript[start:spark_pointer]...)
		}
	}

	sparkConfig.Transcript = spark_truncated_transcript

	internerBytes, err := hex.DecodeString(r1cs.Interner.Values)
	if err != nil {
		return fmt.Errorf("failed to decode interner values: %w", err)
	}

	var interner Interner
	_, err = arkSerialize.CanonicalDeserializeWithMode(
		bytes.NewReader(internerBytes), &interner, false, false,
	)
	if err != nil {
		return fmt.Errorf("failed to deserialize interner: %w", err)
	}

	var hidingSpartanData = consumeWhirData(config.WHIRConfigHidingSpartan, &merklePaths, &stirAnswers)
	var witnessData = consumeWhirData(config.WHIRConfigWitness, &merklePaths, &stirAnswers)

	var sparkSumcheckData = consumeWhirData(sparkConfig.WHIR5, &sparkMerklePaths, &sparkStirAnswers)
	var rowFinal = consumeWhirData(sparkConfig.WHIRRow, &sparkMerklePaths, &sparkStirAnswers)
	var rowwiseSparkMerkle = consumeWhirData(sparkConfig.WHIR3, &sparkMerklePaths, &sparkStirAnswers)
	var colFinal = consumeWhirData(sparkConfig.WHIRCol, &sparkMerklePaths, &sparkStirAnswers)
	var colwiseSparkMerkle = consumeWhirData(sparkConfig.WHIR3, &sparkMerklePaths, &sparkStirAnswers)

	hints := Hints{
		pointRow: pointRow,
		pointCol: pointCol,

		witnessHints:      witnessData,
		spartanHidingHint: hidingSpartanData,

		AHints: SparkMatrixHints{
			claimed:            claimedA,
			sparkSumcheckData:  sparkSumcheckData,
			rowFinalMerkle:     rowFinal,
			rowwiseSparkMerkle: rowwiseSparkMerkle,
			colFinalMerkle:     colFinal,
			colwiseSparkMerkle: colwiseSparkMerkle,

			sparkClaimedEvaluations: sparkClaimedEvaluations[0],

			rowFinalCounter:          rowFinalCounter[0],
			rowRSAddressEvaluation:   rowRSAddressEvaluation[0],
			rowRSValueEvaluation:     rowRSValueEvaluation[0],
			rowRSTimestampEvaluation: rowRSTimestampEvaluation[0],

			colFinalCounter:          colFinalCounter[0],
			colRSAddressEvaluation:   colRSAddressEvaluation[0],
			colRSValueEvaluation:     colRSValueEvaluation[0],
			colRSTimestampEvaluation: colRSTimestampEvaluation[0],
		},
	}

	err = verifyCircuit(deferred, config, sparkConfig, hints, pk, vk, claimedEvaluations, r1cs, interner, buildOps)

	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	return nil
}

func GetPkAndVkFromPath(pkPath string, vkPath string) (*groth16.ProvingKey, *groth16.VerifyingKey, error) {
	var pk *groth16.ProvingKey
	var vk *groth16.VerifyingKey
	if pkPath != "" && vkPath != "" {
		log.Printf("Loading PK/VK from %s, %s", pkPath, vkPath)
		restoredPk, restoredVk, err := keysFromFiles(pkPath, vkPath)
		if err != nil {
			log.Printf("Failed to load keys from files: %v", err)
			return nil, nil, fmt.Errorf("failed to load keys from files: %w", err)
		}
		pk = &restoredPk
		vk = &restoredVk
		log.Printf("Successfully loaded PK/VK")
	}
	return pk, vk, nil
}

func GetPkAndVkFromUrl(pkUrl string, vkUrl string) (*groth16.ProvingKey, *groth16.VerifyingKey, error) {
	var pk *groth16.ProvingKey
	var vk *groth16.VerifyingKey

	if pkUrl != "" && vkUrl != "" {
		log.Printf("Downloading PK/VK from %s, %s", pkUrl, vkUrl)
		restoredPk, restoredVk, err := keysFromUrl(pkUrl, vkUrl)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load keys from url: %w", err)
		}
		pk = &restoredPk
		vk = &restoredVk
		log.Printf("Successfully downloaded and loaded PK/VK")
	}

	return pk, vk, nil
}

func GetR1csFromUrl(r1csUrl string) ([]byte, error) {
	log.Printf("Downloading R1CS from %s", r1csUrl)
	r1csFile, err := downloadFromUrl(r1csUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to download r1cs file from url: %w", err)
	}
	log.Printf("Successfully downloaded")
	return r1csFile, nil
}
