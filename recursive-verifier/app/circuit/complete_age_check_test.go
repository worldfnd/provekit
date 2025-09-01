package circuit

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reilabs/whir-verifier-circuit/app/typeConverters"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"

	gnarkNimue "github.com/reilabs/gnark-nimue"
	arkSerialize "github.com/reilabs/go-ark-serialize"
)

func TestCompleteAgeCheckCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	// outputCcsPath := "./complete_age_check_test.ccs"
	configFile, err := os.ReadFile("../../../noir-examples/noir-passport-examples/complete_age_check/params_for_recursive_verifier")
	r1csFilePath := "../../../noir-examples/noir-passport-examples/complete_age_check/r1cs.json"
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	r1csFile, r1csErr := os.ReadFile(r1csFilePath)
	if r1csErr != nil {
		t.Fatalf("failed to read r1cs file: %v", r1csErr)
	}

	var r1cs R1CS
	if err = json.Unmarshal(r1csFile, &r1cs); err != nil {
		t.Fatalf("failed to unmarshal r1cs JSON: %v", err)
	}

	var config Config
	if err := json.Unmarshal(configFile, &config); err != nil {
		t.Fatalf("failed to unmarshal config JSON: %v", err)
	}

	io := gnarkNimue.IOPattern{}
	ioErr := io.Parse([]byte(config.IOPattern))
	if ioErr != nil {
		fmt.Errorf("failed to parse IO pattern: %v", ioErr)
	}

	var pointer uint64
	var truncated []byte

	var merklePaths []MultiPath[KeccakDigest]
	var stirAnswers [][][]Fp256
	var deferred []Fp256
	var claimedEvaluations ClaimedEvaluations

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
				var path MultiPath[KeccakDigest]
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
					t.Fatalf("failed to deserialize deferred hint: %v", err)
				}
				deferred = append(deferred, deferredTemporary...)
			case "claimed_evaluations":
				_, err = arkSerialize.CanonicalDeserializeWithMode(
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
		t.Fatalf("failed to decode interner values: %v", err)
	}

	var interner Interner
	_, err = arkSerialize.CanonicalDeserializeWithMode(
		bytes.NewReader(internerBytes), &interner, false, false,
	)
	if err != nil {
		t.Fatalf("failed to deserialize interner: %v", err)
	}

	var hidingSpartanData = consumeWhirData(config.WHIRConfigHidingSpartan, &merklePaths, &stirAnswers)
	var witnessData = consumeWhirData(config.WHIRConfigWitness, &merklePaths, &stirAnswers)

	hints := Hints{
		witnessHints:      witnessData,
		spartanHidingHint: hidingSpartanData,
	}

	transcriptT := make([]uints.U8, config.TranscriptLen)
	contTranscript := make([]uints.U8, config.TranscriptLen)

	for i := range config.Transcript {
		transcriptT[i] = uints.NewU8(config.Transcript[i])
	}

	witnessLinearStatementEvaluations := make([]frontend.Variable, 3)
	hidingSpartanLinearStatementEvaluations := make([]frontend.Variable, 1)
	contWitnessLinearStatementEvaluations := make([]frontend.Variable, 3)
	contHidingSpartanLinearStatementEvaluations := make([]frontend.Variable, 1)

	hidingSpartanLinearStatementEvaluations[0] = typeConverters.LimbsToBigIntMod(deferred[0].Limbs)
	witnessLinearStatementEvaluations[0] = typeConverters.LimbsToBigIntMod(deferred[1].Limbs)
	witnessLinearStatementEvaluations[1] = typeConverters.LimbsToBigIntMod(deferred[2].Limbs)
	witnessLinearStatementEvaluations[2] = typeConverters.LimbsToBigIntMod(deferred[3].Limbs)

	fSums, gSums := parseClaimedEvaluations(claimedEvaluations, true)

	matrixA := make([]MatrixCell, len(r1cs.A.Values))
	for i := range len(r1cs.A.RowIndices) {
		end := len(r1cs.A.Values) - 1
		if i < len(r1cs.A.RowIndices)-1 {
			end = int(r1cs.A.RowIndices[i+1] - 1)
		}
		for j := int(r1cs.A.RowIndices[i]); j <= end; j++ {
			matrixA[j] = MatrixCell{
				row:    i,
				column: int(r1cs.A.ColIndices[j]),
				value:  typeConverters.LimbsToBigIntMod(interner.Values[r1cs.A.Values[j]].Limbs),
			}
		}
	}

	matrixB := make([]MatrixCell, len(r1cs.B.Values))
	for i := range len(r1cs.B.RowIndices) {
		end := len(r1cs.B.Values) - 1
		if i < len(r1cs.B.RowIndices)-1 {
			end = int(r1cs.B.RowIndices[i+1] - 1)
		}
		for j := int(r1cs.B.RowIndices[i]); j <= end; j++ {
			matrixB[j] = MatrixCell{
				row:    i,
				column: int(r1cs.B.ColIndices[j]),
				value:  typeConverters.LimbsToBigIntMod(interner.Values[r1cs.B.Values[j]].Limbs),
			}
		}
	}

	matrixC := make([]MatrixCell, len(r1cs.C.Values))
	for i := range len(r1cs.C.RowIndices) {
		end := len(r1cs.C.Values) - 1
		if i < len(r1cs.C.RowIndices)-1 {
			end = int(r1cs.C.RowIndices[i+1] - 1)
		}
		for j := int(r1cs.C.RowIndices[i]); j <= end; j++ {
			matrixC[j] = MatrixCell{
				row:    i,
				column: int(r1cs.C.ColIndices[j]),
				value:  typeConverters.LimbsToBigIntMod(interner.Values[r1cs.C.Values[j]].Limbs),
			}
		}
	}

	var circuit = Circuit{
		IO:                                      []byte(config.IOPattern),
		Transcript:                              contTranscript,
		LogNumConstraints:                       config.LogNumConstraints,
		LogNumVariables:                         config.LogNumVariables,
		LogANumTerms:                            config.LogANumTerms,
		WitnessClaimedEvaluations:               fSums,
		WitnessBlindingEvaluations:              gSums,
		WitnessLinearStatementEvaluations:       contWitnessLinearStatementEvaluations,
		HidingSpartanLinearStatementEvaluations: contHidingSpartanLinearStatementEvaluations,
		HidingSpartanFirstRound:                 newMerkle(hints.spartanHidingHint.firstRoundMerklePaths.path, true),
		HidingSpartanMerkle:                     newMerkle(hints.spartanHidingHint.roundHints, true),
		WitnessMerkle:                           newMerkle(hints.witnessHints.roundHints, true),
		WitnessFirstRound:                       newMerkle(hints.witnessHints.firstRoundMerklePaths.path, true),
		WHIRParamsWitness:                       NewWhirParams(config.WHIRConfigWitness),
		WHIRParamsHidingSpartan:                 NewWhirParams(config.WHIRConfigHidingSpartan),
		MatrixA:                                 matrixA,
		MatrixB:                                 matrixB,
		MatrixC:                                 matrixC,
	}

	// ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	// if err != nil {
	// 	log.Fatalf("Failed to compile circuit: %v", err)
	// }
	// if outputCcsPath != "" {
	// 	ccsFile, err := os.Create(outputCcsPath)
	// 	if err != nil {
	// 		log.Printf("Cannot create ccs file %s: %v", outputCcsPath, err)
	// 	} else {
	// 		_, err = ccs.WriteTo(ccsFile)
	// 		if err != nil {
	// 			log.Printf("Cannot write ccs file %s: %v", outputCcsPath, err)
	// 		}
	// 	}
	// 	log.Printf("ccs written to %s", outputCcsPath)
	// }

	// if pk == nil || vk == nil {
	// 	log.Printf("PK/VK not provided, generating new keys unsafely. Consider providing keys from an MPC ceremony.")
	// 	unsafePk, unsafeVk, err := groth16.Setup(ccs)
	// 	if err != nil {
	// 		log.Fatalf("Failed to setup groth16: %v", err)
	// 	}
	// 	pk = &unsafePk
	// 	vk = &unsafeVk
	// }

	fSums, gSums = parseClaimedEvaluations(claimedEvaluations, false)

	assignment := Circuit{
		IO:                                      []byte(config.IOPattern),
		Transcript:                              transcriptT,
		LogNumConstraints:                       config.LogNumConstraints,
		LogNumVariables:                         config.LogNumVariables,
		LogANumTerms:                            config.LogANumTerms,
		WitnessClaimedEvaluations:               fSums,
		WitnessBlindingEvaluations:              gSums,
		WitnessLinearStatementEvaluations:       witnessLinearStatementEvaluations,
		HidingSpartanLinearStatementEvaluations: hidingSpartanLinearStatementEvaluations,
		HidingSpartanFirstRound:                 newMerkle(hints.spartanHidingHint.firstRoundMerklePaths.path, false),
		HidingSpartanMerkle:                     newMerkle(hints.spartanHidingHint.roundHints, false),
		WitnessMerkle:                           newMerkle(hints.witnessHints.roundHints, false),
		WitnessFirstRound:                       newMerkle(hints.witnessHints.firstRoundMerklePaths.path, false),
		WHIRParamsWitness:                       NewWhirParams(config.WHIRConfigWitness),
		WHIRParamsHidingSpartan:                 NewWhirParams(config.WHIRConfigHidingSpartan),
		MatrixA:                                 matrixA,
		MatrixB:                                 matrixB,
		MatrixC:                                 matrixC,
	}

	// witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	// publicWitness, _ := witness.Public()

	assert.CheckCircuit(
		&circuit,
		test.WithValidAssignment(&assignment),
		test.WithCurves(ecc.BN254),
	)
}
