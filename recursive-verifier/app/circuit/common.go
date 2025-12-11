package circuit

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/consensys/gnark/backend/groth16"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	arkSerialize "github.com/reilabs/go-ark-serialize"

	"reilabs/whir-verifier-circuit/app/common"
)

func PrepareAndVerifyCircuit(config Config, r1cs R1CS, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, buildOps common.BuildOps) error {
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
	var claimedEvaluations2 ClaimedEvaluations

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
			default:
				// Handle batch-mode hints: stir_answers_witness_X and merkle_proof_witness_X
				label := string(op.Label)
				if strings.HasPrefix(label, "merkle_proof_witness_") {
					var path FullMultiPath[KeccakDigest]
					_, err = arkSerialize.CanonicalDeserializeWithMode(
						bytes.NewReader(config.Transcript[start:end]),
						&path,
						false, false,
					)
					merklePaths = append(merklePaths, path)
				} else if strings.HasPrefix(label, "stir_answers_witness_") {
					var stirAnswersTemporary [][]Fp256
					_, err = arkSerialize.CanonicalDeserializeWithMode(
						bytes.NewReader(config.Transcript[start:end]),
						&stirAnswersTemporary,
						false, false,
					)
					stirAnswers = append(stirAnswers, stirAnswersTemporary)
				}

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

			// Single mode hint
			case "claimed_evaluations":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&claimedEvaluations,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize claimed_evaluations: %w", err)
				}

			// Dual mode hints
			case "claimed_evaluations_1":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&claimedEvaluations,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize claimed_evaluations_1: %w", err)
				}

			case "claimed_evaluations_2":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&claimedEvaluations2,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize claimed_evaluations_2: %w", err)
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

	hidingSpartanData := consumeWhirData(config.WHIRConfigHidingSpartan, &merklePaths, &stirAnswers)

	// Build witness hints based on mode
	var witnessFirstRoundHints []FirstRoundHint
	var witnessRoundHints ZKHint

	if config.NumChallenges > 0 {
		// Batch mode: N commitments
		// Rust emits: N first-round hints, then NRounds hints for batched polynomial
		var numCommitments int
		if config.NumChallenges > 0 {
			numCommitments = 2
		} else {
			numCommitments = 1
		}

		// Consume first-round hints for each original commitment
		witnessFirstRoundHints = make([]FirstRoundHint, numCommitments)
		for i := 0; i < numCommitments; i++ {
			witnessFirstRoundHints[i] = consumeFirstRoundOnly(&merklePaths, &stirAnswers)
		}

		// Consume rounds 1+ for the batched polynomial
		witnessRoundHints = consumeWhirDataRoundsOnly(config.WHIRConfigWitness, &merklePaths, &stirAnswers)
	} else {
		// Single mode
		witnessData := consumeWhirData(config.WHIRConfigWitness, &merklePaths, &stirAnswers)
		witnessFirstRoundHints = []FirstRoundHint{witnessData.firstRoundMerklePaths}
		witnessRoundHints = witnessData
	}

	hints := Hints{
		spartanHidingHint:      hidingSpartanData,
		WitnessFirstRoundHints: witnessFirstRoundHints,
		WitnessRoundHints:      witnessRoundHints,
	}

	err = verifyCircuit(deferred, config, hints, pk, vk, claimedEvaluations, claimedEvaluations2, r1cs, interner, buildOps)
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
