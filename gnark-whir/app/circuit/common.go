package circuit

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/consensys/gnark/backend/groth16"

	gnark_nimue "github.com/reilabs/gnark-nimue"
	go_ark_serialize "github.com/reilabs/go-ark-serialize"
)

func PrepareAndVerifyCircuit(config Config, r1cs R1CS, vkPath string, pkPath string, outputCcsPath string) error {

	io := gnark_nimue.IOPattern{}
	err := io.Parse([]byte(config.IOPattern))
	if err != nil {
		return fmt.Errorf("failed to parse IO pattern: %w", err)
	}

	var pointer uint64
	var truncated []byte

	var merklePaths []MultiPath[KeccakDigest]
	var stirAnswers [][][]Fp256
	var deferred []Fp256
	var claimedEvaluations []Fp256

	for _, op := range io.Ops {
		switch op.Kind {
		case gnark_nimue.Hint:
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
				var path MultiPath[KeccakDigest]
				_, err = go_ark_serialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&path,
					false, false,
				)
				merklePaths = append(merklePaths, path)
			case "stir_answers":
				var stirAnswersTemporary [][]Fp256
				_, err = go_ark_serialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&stirAnswersTemporary,
					false, false,
				)
				stirAnswers = append(stirAnswers, stirAnswersTemporary)
			case "deferred_weight_evaluations":
				var deferredTemporary []Fp256
				_, err = go_ark_serialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&deferredTemporary,
					false, false,
				)
				if err != nil {
					return fmt.Errorf("failed to deserialize deferred hint: %w", err)
				}
				deferred = append(deferred, deferredTemporary...)
			case "claimed_evaluations":
				_, err = go_ark_serialize.CanonicalDeserializeWithMode(
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

		case gnark_nimue.Absorb:
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
	_, err = go_ark_serialize.CanonicalDeserializeWithMode(
		bytes.NewReader(internerBytes), &interner, false, false,
	)
	if err != nil {
		return fmt.Errorf("failed to deserialize interner: %w", err)
	}

	var pk *groth16.ProvingKey
	var vk *groth16.VerifyingKey
	if pkPath != "" && vkPath != "" {
		log.Printf("Loading PK/VK from %s, %s", pkPath, vkPath)
		restoredPk, restoredVk, err := KeysFromFiles(pkPath, vkPath)
		if err != nil {
			log.Printf("Failed to load keys from files: %v", err)
			return fmt.Errorf("failed to load keys from files: %w", err)
		}
		pk = &restoredPk
		vk = &restoredVk
		log.Printf("Successfully loaded PK/VK")
	}

	spartanEnd := config.WHIRConfigCol.NRounds + 1

	hints := Hints{
		ColHints: Hint{
			MerklePaths: merklePaths[:spartanEnd],
			StirAnswers: stirAnswers[:spartanEnd],
		},
	}

	err = verifyCircuit(deferred, config, hints, pk, vk, outputCcsPath, claimedEvaluations, r1cs, interner)
	if err != nil {
		return fmt.Errorf("failed to verify circuit: %w", err)
	}

	return nil
}
