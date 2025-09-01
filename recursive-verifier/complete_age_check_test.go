package circuit

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"reilabs/whir-verifier-circuit/app/circuit"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	gnarkNimue "github.com/reilabs/gnark-nimue"
	arkSerialize "github.com/reilabs/go-ark-serialize"
)

func TestCompleteAgeCheckCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	configFile, err := os.ReadFile("../noir-examples/noir-passport-examples/complete_age_check/params_for_recursive_verifier")
	r1csFilePath := "../noir-examples/noir-passport-examples/complete_age_check/r1cs.json"
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	r1csFile, r1csErr := os.ReadFile(r1csFilePath)
	if r1csErr != nil {
		t.Fatalf("failed to read r1cs file: %v", r1csErr)
	}

	var r1cs circuit.R1CS
	if err = json.Unmarshal(r1csFile, &r1cs); err != nil {
		t.Fatalf("failed to unmarshal r1cs JSON: %v", err)
	}

	var config circuit.Config
	if err := json.Unmarshal(configFile, &config); err != nil {
		t.Fatalf("failed to unmarshal config JSON: %v", err)
	}

	io := gnarkNimue.IOPattern{}
	ioErr := io.Parse([]byte(config.IOPattern))
	if ioErr != nil {
		fmt.Errorf("failed to parse IO pattern: %w", err)
	}

	var pointer uint64
	var truncated []byte

	var merklePaths []circuit.MultiPath[circuit.KeccakDigest]
	var stirAnswers [][][]circuit.Fp256
	var deferred []circuit.Fp256
	var claimedEvaluations circuit.ClaimedEvaluations

	for _, op := range io.Ops {
		switch op.Kind {
		case gnarkNimue.Hint:
			if pointer+4 > uint64(len(config.Transcript)) {
				t.Fatalf("insufficient bytes for hint length")
			}
			hintLen := binary.LittleEndian.Uint32(config.Transcript[pointer : pointer+4])
			start := pointer + 4
			end := start + uint64(hintLen)

			if end > uint64(len(config.Transcript)) {
				t.Fatalf("insufficient bytes for merkle proof")
			}

			switch string(op.Label) {
			case "merkle_proof":
				var path circuit.MultiPath[circuit.KeccakDigest]
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&path,
					false, false,
				)
				merklePaths = append(merklePaths, path)

			case "stir_answers":
				var stirAnswersTemporary [][]circuit.Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&stirAnswersTemporary,
					false, false,
				)
				stirAnswers = append(stirAnswers, stirAnswersTemporary)

			case "deferred_weight_evaluations":
				var deferredTemporary []circuit.Fp256
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&deferredTemporary,
					false, false,
				)
				if err != nil {
					t.Fatalf("failed to deserialize deferred hint: %w", err)
				}
				deferred = append(deferred, deferredTemporary...)
			case "claimed_evaluations":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&claimedEvaluations,
					false, false,
				)
				if err != nil {
					t.Fatalf("failed to deserialize claimed_evaluations: %w", err)
				}
			}

			if err != nil {
				t.Fatalf("failed to deserialize merkle proof: %w", err)
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
				t.Fatalf("absorb exceeds transcript length")
			}

			truncated = append(truncated, config.Transcript[start:pointer]...)
		}
	}

	config.Transcript = truncated

	internerBytes, err := hex.DecodeString(r1cs.Interner.Values)
	if err != nil {
		t.Fatalf("failed to decode interner values: %w", err)
	}

	var interner circuit.Interner
	_, err = arkSerialize.CanonicalDeserializeWithMode(
		bytes.NewReader(internerBytes), &interner, false, false,
	)
	if err != nil {
		t.Fatalf("failed to deserialize interner: %w", err)
	}

	var hidingSpartanData = consumeWhirData(config.WHIRConfigHidingSpartan, &merklePaths, &stirAnswers)
	var witnessData = consumeWhirData(config.WHIRConfigWitness, &merklePaths, &stirAnswers)

	hints := Hints{
		witnessHints:      witnessData,
		spartanHidingHint: hidingSpartanData,
	}

	assert.CheckCircuit(
		&circuit,
		test.WithValidAssignment(&assignment),
		test.WithCurves(ecc.BN254),
	)
}
