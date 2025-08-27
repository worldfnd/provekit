package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"reilabs/whir-verifier-circuit/typeConverters"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	gnark_nimue "github.com/reilabs/gnark-nimue"
	go_ark_serialize "github.com/reilabs/go-ark-serialize"
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

	var internedR1CS R1CS
	if err = json.Unmarshal(r1csFile, &internedR1CS); err != nil {
		t.Fatalf("failed to unmarshal r1cs JSON: %v", err)
	}

	var config Config
	if err := json.Unmarshal(configFile, &config); err != nil {
		t.Fatalf("failed to unmarshal config JSON: %v", err)
	}

	io := gnark_nimue.IOPattern{}
	err = io.Parse([]byte(config.IOPattern))
	if err != nil {
		t.Fatalf("failed to parse IO pattern: %v", err)
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
					t.Fatalf("failed to deserialize deferred hint: %v", err)
				}
				deferred = append(deferred, deferredTemporary...)
			case "claimed_evaluations":
				_, err = go_ark_serialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&claimedEvaluations,
					false, false,
				)
				if err != nil {
					t.Fatalf("failed to deserialize claimed_evaluations: %v", err)
				}
			}

			if err != nil {
				t.Fatalf("failed to deserialize merkle proof: %v", err)
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
				t.Fatalf("absorb exceeds transcript length")
			}

			truncated = append(truncated, config.Transcript[start:pointer]...)
		}
	}

	config.Transcript = truncated

	internerBytes, err := hex.DecodeString(internedR1CS.Interner.Values)
	if err != nil {
		t.Fatalf("failed to decode interner values: %v", err)
	}

	var interner Interner
	_, err = go_ark_serialize.CanonicalDeserializeWithMode(
		bytes.NewReader(internerBytes), &interner, false, false,
	)
	if err != nil {
		t.Fatalf("failed to deserialize interner: %v", err)
	}

	spartanEnd := config.WHIRConfigCol.NRounds + 1

	hints := Hints{
		colHints: Hint{
			merklePaths: merklePaths[:spartanEnd],
			stirAnswers: stirAnswers[:spartanEnd],
		},
	}

	transcriptT := make([]uints.U8, config.TranscriptLen)
	contTranscript := make([]uints.U8, config.TranscriptLen)

	for i := range config.Transcript {
		transcriptT[i] = uints.NewU8(config.Transcript[i])
	}

	linearStatementValuesAtPoints := make([]frontend.Variable, len(deferred))
	contLinearStatementValuesAtPoints := make([]frontend.Variable, len(deferred))

	linearStatementEvaluations := make([]frontend.Variable, len(claimedEvaluations))
	contLinearStatementEvaluations := make([]frontend.Variable, len(claimedEvaluations))
	for i := range len(deferred) {
		linearStatementValuesAtPoints[i] = typeConverters.LimbsToBigIntMod(deferred[i].Limbs)
		linearStatementEvaluations[i] = typeConverters.LimbsToBigIntMod(claimedEvaluations[i].Limbs)
	}

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

	assignment := Circuit{
		IO:                []byte(config.IOPattern),
		Transcript:        transcriptT,
		LogNumConstraints: config.LogNumConstraints,

		LinearStatementEvaluations:    linearStatementEvaluations,
		LinearStatementValuesAtPoints: linearStatementValuesAtPoints,
		SpartanMerkle:                 newMerkle(hints.colHints, false),

		MatrixA: matrixA,
		MatrixB: matrixB,
		MatrixC: matrixC,

		WHIRParamsCol: new_whir_params(config.WHIRConfigCol),
	}

	// witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	var circuit = Circuit{
		IO:                []byte(config.IOPattern),
		Transcript:        contTranscript,
		LogNumConstraints: config.LogNumConstraints,
		LogNumVariables:   config.LogNumVariables,

		LinearStatementEvaluations:    contLinearStatementEvaluations,
		LinearStatementValuesAtPoints: contLinearStatementValuesAtPoints,
		SpartanMerkle:                 newMerkle(hints.colHints, true),

		MatrixA: matrixA,
		MatrixB: matrixB,
		MatrixC: matrixC,

		WHIRParamsCol: new_whir_params(config.WHIRConfigCol),
	}

	assert.CheckCircuit(
		&circuit,
		test.WithValidAssignment(&assignment),
		test.WithCurves(ecc.BN254),
	)
}
