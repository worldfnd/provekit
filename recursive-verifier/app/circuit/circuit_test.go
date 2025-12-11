package circuit

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"reilabs/whir-verifier-circuit/app/typeConverters"
	"reilabs/whir-verifier-circuit/app/utilities"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	arkSerialize "github.com/reilabs/go-ark-serialize"
)

// TestCircuitConstraints checks that the circuit constraints are satisfied
// without generating/verifying a full Groth16 proof.
// This is much faster for testing purposes.
func TestCircuitConstraints(t *testing.T) {
	// Skip if test fixtures don't exist
	configPath := os.Getenv("TEST_CONFIG_PATH")
	r1csPath := os.Getenv("TEST_R1CS_PATH")

	if configPath == "" || r1csPath == "" {
		t.Skip("Skipping test: TEST_CONFIG_PATH and TEST_R1CS_PATH env vars not set")
	}

	// Load config
	configFile, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(configFile, &config); err != nil {
		t.Fatalf("Failed to unmarshal config JSON: %v", err)
	}

	// Load R1CS
	r1csFile, err := os.ReadFile(r1csPath)
	if err != nil {
		t.Fatalf("Failed to read r1cs file: %v", err)
	}

	var r1csData R1CS
	if err := json.Unmarshal(r1csFile, &r1csData); err != nil {
		t.Fatalf("Failed to unmarshal r1cs JSON: %v", err)
	}

	// Build circuit and assignment
	circuit, assignment, err := buildCircuitAndAssignment(config, r1csData)
	if err != nil {
		t.Fatalf("Failed to build circuit and assignment: %v", err)
	}

	// Use gnark's test framework to check constraint satisfaction
	assert := test.NewAssert(t)
	assert.CheckCircuit(
		circuit,
		test.WithValidAssignment(assignment),
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.WithSolverOpts(solver.WithHints(utilities.IndexOf)),
	)
}

// TestCircuitConstraintsSolverOnly uses just the solver to check if constraints are satisfied.
// Even faster than CheckCircuit as it skips backend-specific checks.
func TestCircuitConstraintsSolverOnly(t *testing.T) {
	configPath := os.Getenv("TEST_CONFIG_PATH")
	r1csPath := os.Getenv("TEST_R1CS_PATH")

	if configPath == "" || r1csPath == "" {
		t.Skip("Skipping test: TEST_CONFIG_PATH and TEST_R1CS_PATH env vars not set")
	}

	configFile, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(configFile, &config); err != nil {
		t.Fatalf("Failed to unmarshal config JSON: %v", err)
	}

	r1csFile, err := os.ReadFile(r1csPath)
	if err != nil {
		t.Fatalf("Failed to read r1cs file: %v", err)
	}

	var r1csData R1CS
	if err := json.Unmarshal(r1csFile, &r1csData); err != nil {
		t.Fatalf("Failed to unmarshal r1cs JSON: %v", err)
	}

	circuit, assignment, err := buildCircuitAndAssignment(config, r1csData)
	if err != nil {
		t.Fatalf("Failed to build circuit and assignment: %v", err)
	}

	// Compile circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}

	t.Logf("Circuit compiled: %d constraints", ccs.GetNbConstraints())

	// Create witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	// Solve the constraint system
	_, err = ccs.Solve(witness, solver.WithHints(utilities.IndexOf))
	if err != nil {
		t.Fatalf("Constraint system not satisfied: %v", err)
	}

	t.Log("All constraints satisfied!")
}

// buildCircuitAndAssignment constructs both the circuit definition and the witness assignment
// from the config and r1cs data. This mirrors what verifyCircuit does but separates
// circuit (placeholder) from assignment (actual values).
func buildCircuitAndAssignment(config Config, r1csData R1CS) (*Circuit, *Circuit, error) {
	// Parse transcript and extract hints
	io := gnarkNimue.IOPattern{}
	if err := io.Parse([]byte(config.IOPattern)); err != nil {
		return nil, nil, err
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
				return nil, nil, nil
			}
			hintLen := binary.LittleEndian.Uint32(config.Transcript[pointer : pointer+4])
			start := pointer + 4
			end := start + uint64(hintLen)

			switch string(op.Label) {
			default:
				// Handle batch-mode hints: stir_answers_witness_X and merkle_proof_witness_X
				label := string(op.Label)
				if strings.HasPrefix(label, "merkle_proof_witness_") {
					var path FullMultiPath[KeccakDigest]
					_, err := arkSerialize.CanonicalDeserializeWithMode(
						bytes.NewReader(config.Transcript[start:end]),
						&path,
						false, false,
					)
					if err != nil {
						return nil, nil, err
					}
					merklePaths = append(merklePaths, path)
				} else if strings.HasPrefix(label, "stir_answers_witness_") {
					var stirAnswersTemporary [][]Fp256
					_, err := arkSerialize.CanonicalDeserializeWithMode(
						bytes.NewReader(config.Transcript[start:end]),
						&stirAnswersTemporary,
						false, false,
					)
					if err != nil {
						return nil, nil, err
					}
					stirAnswers = append(stirAnswers, stirAnswersTemporary)
				}

			case "merkle_proof":
				var path FullMultiPath[KeccakDigest]
				_, _ = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&path, false, false,
				)
				merklePaths = append(merklePaths, path)

			case "stir_answers":
				var stirAnswersTemporary [][]Fp256
				_, _ = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&stirAnswersTemporary, false, false,
				)
				stirAnswers = append(stirAnswers, stirAnswersTemporary)

			case "deferred_weight_evaluations":
				var deferredTemporary []Fp256
				_, _ = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&deferredTemporary, false, false,
				)
				deferred = append(deferred, deferredTemporary...)

			case "claimed_evaluations":
				_, _ = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&claimedEvaluations, false, false,
				)

			case "claimed_evaluations_1":
				_, _ = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&claimedEvaluations, false, false,
				)

			case "claimed_evaluations_2":
				_, _ = arkSerialize.CanonicalDeserializeWithMode(
					bytes.NewReader(config.Transcript[start:end]),
					&claimedEvaluations2, false, false,
				)
			}
			pointer = end

		case gnarkNimue.Absorb:
			start := pointer
			if string(op.Label) == "pow-nonce" {
				pointer += op.Size
			} else {
				pointer += op.Size * 32
			}
			truncated = append(truncated, config.Transcript[start:pointer]...)
		}
	}

	config.Transcript = truncated

	// Parse interner
	internerBytes, err := hex.DecodeString(r1csData.Interner.Values)
	if err != nil {
		return nil, nil, err
	}

	var interner Interner
	_, err = arkSerialize.CanonicalDeserializeWithMode(
		bytes.NewReader(internerBytes), &interner, false, false,
	)
	if err != nil {
		return nil, nil, err
	}

	// Build hints
	hidingSpartanData := consumeWhirData(config.WHIRConfigHidingSpartan, &merklePaths, &stirAnswers)

	var witnessFirstRoundHints []FirstRoundHint
	var witnessRoundHints ZKHint

	if config.NumChallenges > 0 {
		numCommitments := 2
		witnessFirstRoundHints = make([]FirstRoundHint, numCommitments)
		for i := 0; i < numCommitments; i++ {
			witnessFirstRoundHints[i] = consumeFirstRoundOnly(&merklePaths, &stirAnswers)
		}
		witnessRoundHints = consumeWhirDataRoundsOnly(config.WHIRConfigWitness, &merklePaths, &stirAnswers)
	} else {
		witnessData := consumeWhirData(config.WHIRConfigWitness, &merklePaths, &stirAnswers)
		witnessFirstRoundHints = []FirstRoundHint{witnessData.firstRoundMerklePaths}
		witnessRoundHints = witnessData
	}

	hints := Hints{
		spartanHidingHint:      hidingSpartanData,
		WitnessFirstRoundHints: witnessFirstRoundHints,
		WitnessRoundHints:      witnessRoundHints,
	}

	// Build matrices
	matrixA := buildMatrix(r1csData.A, interner)
	matrixB := buildMatrix(r1csData.B, interner)
	matrixC := buildMatrix(r1csData.C, interner)

	// Parse evaluations
	witnessLinearStatementEvaluations := make([]frontend.Variable, 3)
	hidingSpartanLinearStatementEvaluations := make([]frontend.Variable, 1)

	hidingSpartanLinearStatementEvaluations[0] = typeConverters.LimbsToBigIntMod(deferred[0].Limbs)
	witnessLinearStatementEvaluations[0] = typeConverters.LimbsToBigIntMod(deferred[1].Limbs)
	witnessLinearStatementEvaluations[1] = typeConverters.LimbsToBigIntMod(deferred[2].Limbs)
	witnessLinearStatementEvaluations[2] = typeConverters.LimbsToBigIntMod(deferred[3].Limbs)

	// Build transcript
	transcriptT := make([]uints.U8, config.TranscriptLen)
	contTranscript := make([]uints.U8, config.TranscriptLen)
	for i := range config.Transcript {
		transcriptT[i] = uints.NewU8(config.Transcript[i])
	}

	// Parse claimed evaluations
	fSums, gSums := parseClaimedEvaluations(claimedEvaluations, true)
	var fSums2, gSums2 []frontend.Variable
	if config.NumChallenges > 0 {
		fSums2, gSums2 = parseClaimedEvaluations(claimedEvaluations2, true)
	}

	// Build the slices conditionally
	var witnessClaimedEvals, witnessBlindingEvals [][]frontend.Variable
	if config.NumChallenges > 0 {
		witnessClaimedEvals = [][]frontend.Variable{fSums, fSums2}
		witnessBlindingEvals = [][]frontend.Variable{gSums, gSums2}
	} else {
		witnessClaimedEvals = [][]frontend.Variable{fSums}
		witnessBlindingEvals = [][]frontend.Variable{gSums}
	}

	// Build circuit definition (with placeholder values)
	circuit := &Circuit{
		IO:                                      []byte(config.IOPattern),
		Transcript:                              contTranscript,
		LogNumConstraints:                       config.LogNumConstraints,
		LogNumVariables:                         config.LogNumVariables,
		LogANumTerms:                            config.LogANumTerms,
		WitnessClaimedEvaluations:               witnessClaimedEvals,
		WitnessBlindingEvaluations:              witnessBlindingEvals,
		WitnessLinearStatementEvaluations:       make([]frontend.Variable, 3),
		HidingSpartanLinearStatementEvaluations: make([]frontend.Variable, 1),
		HidingSpartanFirstRound:                 newMerkle(hints.spartanHidingHint.firstRoundMerklePaths.path, true),
		HidingSpartanMerkle:                     newMerkle(hints.spartanHidingHint.roundHints, true),
		WitnessFirstRounds:                      witnessFirstRounds(hints, true),
		BatchedWitnessMerkle:                    newMerkle(hints.WitnessRoundHints.roundHints, true),
		NumChallenges:                           config.NumChallenges,
		WHIRParamsWitness:                       NewWhirParams(config.WHIRConfigWitness),
		WHIRParamsHidingSpartan:                 NewWhirParams(config.WHIRConfigHidingSpartan),
		MatrixA:                                 matrixA,
		MatrixB:                                 matrixB,
		MatrixC:                                 matrixC,
	}

	// Build assignment (with actual values)
	fSumsAssign, gSumsAssign := parseClaimedEvaluations(claimedEvaluations, false)
	var fSums2Assign, gSums2Assign []frontend.Variable
	var witnessClaimedEvalsAssign, witnessBlindingEvalsAssign [][]frontend.Variable
	if config.NumChallenges > 0 {
		fSums2Assign, gSums2Assign = parseClaimedEvaluations(claimedEvaluations2, false)
		witnessClaimedEvalsAssign = [][]frontend.Variable{fSumsAssign, fSums2Assign}
		witnessBlindingEvalsAssign = [][]frontend.Variable{gSumsAssign, gSums2Assign}
	} else {
		witnessClaimedEvalsAssign = [][]frontend.Variable{fSumsAssign}
		witnessBlindingEvalsAssign = [][]frontend.Variable{gSumsAssign}
	}

	assignment := &Circuit{
		IO:                                      []byte(config.IOPattern),
		Transcript:                              transcriptT,
		LogNumConstraints:                       config.LogNumConstraints,
		WitnessClaimedEvaluations:               witnessClaimedEvalsAssign,
		WitnessBlindingEvaluations:              witnessBlindingEvalsAssign,
		WitnessLinearStatementEvaluations:       witnessLinearStatementEvaluations,
		HidingSpartanLinearStatementEvaluations: hidingSpartanLinearStatementEvaluations,
		HidingSpartanFirstRound:                 newMerkle(hints.spartanHidingHint.firstRoundMerklePaths.path, false),
		HidingSpartanMerkle:                     newMerkle(hints.spartanHidingHint.roundHints, false),
		WitnessFirstRounds:                      witnessFirstRounds(hints, false),
		BatchedWitnessMerkle:                    newMerkle(hints.WitnessRoundHints.roundHints, false),
		NumChallenges:                           config.NumChallenges,
		WHIRParamsWitness:                       NewWhirParams(config.WHIRConfigWitness),
		WHIRParamsHidingSpartan:                 NewWhirParams(config.WHIRConfigHidingSpartan),
		MatrixA:                                 matrixA,
		MatrixB:                                 matrixB,
		MatrixC:                                 matrixC,
	}

	return circuit, assignment, nil
}

func buildMatrix(sparse SparseMatrix, interner Interner) []MatrixCell {
	matrix := make([]MatrixCell, len(sparse.Values))
	for i := range len(sparse.RowIndices) {
		end := len(sparse.Values) - 1
		if i < len(sparse.RowIndices)-1 {
			end = int(sparse.RowIndices[i+1] - 1)
		}
		for j := int(sparse.RowIndices[i]); j <= end; j++ {
			matrix[j] = MatrixCell{
				row:    i,
				column: int(sparse.ColIndices[j]),
				value:  typeConverters.LimbsToBigIntMod(interner.Values[sparse.Values[j]].Limbs),
			}
		}
	}
	return matrix
}
