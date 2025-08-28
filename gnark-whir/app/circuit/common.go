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
)

func PrepareAndVerifyCircuit(config Config, r1cs R1CS, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, outputCcsPath string) error {
	io := gnarkNimue.IOPattern{}
	err := io.Parse([]byte(config.IOPattern))
	if err != nil {
		return fmt.Errorf("failed to parse IO pattern: %w", err)
	}
	fmt.Printf("io: %s\n", io.PPrint())

	var pointer uint64
	var truncated []byte

	var merkle_paths []MultiPath[KeccakDigest]
	var stir_answers [][][]Fp256
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
				var path MultiPath[KeccakDigest]
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&path,
					false, false,
				)
				merkle_paths = append(merkle_paths, path)

			case "stir_answers":
				var stirAnswersTemporary [][]Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&stirAnswersTemporary,
					false, false,
				)
				stir_answers = append(stir_answers, stirAnswersTemporary)

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

	var hidingSpartanData = consumeWhirData(config.WHIRConfigHidingSpartan, &merkle_paths, &stir_answers)

	var witnessData = consumeWhirData(config.WHIRConfigWitness, &merkle_paths, &stir_answers)

	hints := Hints{
		witnessHints:      witnessData,
		spartanHidingHint: hidingSpartanData,
	}
	verifyCircuit(deferred, config, hints, pk, vk, outputCcsPath, claimedEvaluations, r1cs, interner)
	return nil
}

func GetPkAndVkFromPath(pkPath string, vkPath string) (*groth16.ProvingKey, *groth16.VerifyingKey, error) {

	var pk *groth16.ProvingKey = nil
	var vk *groth16.VerifyingKey = nil
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
	var pk *groth16.ProvingKey = nil
	var vk *groth16.VerifyingKey = nil

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
