package circuit

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"reilabs/whir-verifier-circuit/app/utilities"
	"reilabs/whir-verifier-circuit/app/whir"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

// TestCircuitConstraints checks that the circuit constraints are satisfied
// without generating/verifying a full Groth16 proof.
// This is much faster for testing purposes.
func TestCircuitConstraints(t *testing.T) {
	configPath := os.Getenv("TEST_CONFIG_PATH")
	r1csPath := os.Getenv("TEST_R1CS_PATH")

	if configPath == "" || r1csPath == "" {
		t.Skip("Skipping test: TEST_CONFIG_PATH and TEST_R1CS_PATH env vars not set")
	}

	config, r1csData := loadTestData(t, configPath, r1csPath)

	circuit, assignment, err := buildCircuitAndAssignment(config, r1csData)
	if err != nil {
		t.Fatalf("Failed to build circuit and assignment: %v", err)
	}

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

	config, r1csData := loadTestData(t, configPath, r1csPath)

	circuit, assignment, err := buildCircuitAndAssignment(config, r1csData)
	if err != nil {
		t.Fatalf("Failed to build circuit and assignment: %v", err)
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("Failed to compile circuit: %v", err)
	}

	t.Logf("Circuit compiled: %d constraints", ccs.GetNbConstraints())

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	_, err = ccs.Solve(witness, solver.WithHints(utilities.IndexOf))
	if err != nil {
		t.Fatalf("Constraint system not satisfied: %v", err)
	}

	t.Log("All constraints satisfied!")
}

func loadTestData(t *testing.T, configPath, r1csPath string) (Config, R1CS) {
	t.Helper()

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

	return config, r1csData
}

// buildCircuitAndAssignment replays the Fiat-Shamir transcript natively
// (like PrepareAndVerifyCircuit) and then builds the gnark Circuit template
// and assignment (like verifyCircuit), returning both for test use.
func buildCircuitAndAssignment(config Config, r1csData R1CS) (*Circuit, *Circuit, error) {
	if len(config.ProtocolID) < 64 {
		return nil, nil, fmt.Errorf("protocol_id must be 64 bytes, got %d", len(config.ProtocolID))
	}
	var pid [64]byte
	copy(pid[:], config.ProtocolID[:64])

	// Compute instance = public_inputs.hash_bytes() to bind public inputs to the transcript.
	piValues := make([]*big.Int, len(config.PublicInputs.Values))
	for i, v := range config.PublicInputs.Values {
		piValues[i] = v.(*big.Int)
	}
	instance := nativePublicInputsHashBytes(piValues)

	nimue := NewNativeNimue(pid, config.SessionID, instance, config.NargString, config.Hints)
	blindedCommitmentWhirConfig := NewWhirParams(config.BlindedCommitmentWhirConfig)
	blindingCommitmentWhirConfig := NewWhirParams(config.BlindingCommitmentWhirConfig)

	// 1. Parse commitment 1
	_, blindedOODPoints, blindedOODMatrix, err := nativeParseBatchedCommitment(nimue, blindedCommitmentWhirConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("parse blinded commitment: %w", err)
	}
	blindedCommitment := NativeCommitmentFromParsed(blindedOODPoints, blindedOODMatrix)

	_, blindingOODPoints, blindingOODMatrix, err := nativeParseBatchedCommitment(nimue, blindingCommitmentWhirConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("parse blinding commitment: %w", err)
	}
	blindingCommitment := NativeCommitmentFromParsed(blindingOODPoints, blindingOODMatrix)

	// 2. If dual mode: squeeze logup challenges, parse commitment 2
	if config.NumChallenges > 0 {
		if _, err = nimue.FillChallengeScalars(config.NumChallenges); err != nil {
			return nil, nil, fmt.Errorf("logup challenges: %w", err)
		}
		if _, _, _, err = nativeParseBatchedCommitment(nimue, blindedCommitmentWhirConfig); err != nil {
			return nil, nil, fmt.Errorf("parse commitment 2 blinded: %w", err)
		}
		if _, _, _, err = nativeParseBatchedCommitment(nimue, blindingCommitmentWhirConfig); err != nil {
			return nil, nil, fmt.Errorf("parse commitment 2 blinding: %w", err)
		}
	}

	// 3. Sumcheck
	if _, err = nativeRunSumcheckVerifier(nimue, config.LogNumConstraints); err != nil {
		return nil, nil, fmt.Errorf("sumcheck verifier: %w", err)
	}

	// 4. Public inputs hash + x challenge
	if _, err = nimue.FillNextScalars(1); err != nil {
		return nil, nil, fmt.Errorf("public inputs hash: %w", err)
	}
	if _, err = nimue.FillChallengeScalars(1); err != nil {
		return nil, nil, fmt.Errorf("x challenge: %w", err)
	}

	// 5. Read evaluation hints
	var evals1 []Fp256
	if err = nimue.ProverHintArk(&evals1); err != nil {
		return nil, nil, fmt.Errorf("evals_1: %w", err)
	}
	evals1BigInt := fp256SliceToBigInt(evals1)

	var evals2BigInt []*big.Int
	if config.NumChallenges > 0 {
		var evals2 []Fp256
		if err = nimue.ProverHintArk(&evals2); err != nil {
			return nil, nil, fmt.Errorf("evals_2: %w", err)
		}
		evals2BigInt = fp256SliceToBigInt(evals2)
	}

	hasPublicInputs := !config.PublicInputs.IsEmpty()
	if hasPublicInputs {
		if _, err = nimue.FillNextScalars(1); err != nil {
			return nil, nil, fmt.Errorf("public_eval: %w", err)
		}
	}

	// 6. zkWHIR verify (commitment 1)
	zkWhirParams := newZKWhirVerifyParams(1, hasPublicInputs)
	zkWhirData1, err := nativeZKWhirVerify(nimue, config, blindedCommitmentWhirConfig, blindingCommitmentWhirConfig, zkWhirParams, blindedCommitment, blindingCommitment, evals1BigInt)
	if err != nil {
		return nil, nil, fmt.Errorf("zkWHIR verify commitment 1: %w", err)
	}

	// 7. If dual mode: zkWHIR verify (commitment 2)
	var dualData *DualCommitmentData
	if config.NumChallenges > 0 {
		zkWhirParams2 := ZKWhirVerifyParams{NumPolynomials: 1, WeightsLen: 3}
		zkWhirData2, err := nativeZKWhirVerify(nimue, config, blindedCommitmentWhirConfig, blindingCommitmentWhirConfig, zkWhirParams2, blindedCommitment, blindingCommitment, evals2BigInt)
		if err != nil {
			return nil, nil, fmt.Errorf("zkWHIR verify commitment 2: %w", err)
		}
		dualData = &DualCommitmentData{
			Evals2BigInt:       evals2BigInt,
			BlindedMerkleData:  *zkWhirData2.BlindedMerkleData,
			BlindingMerkleData: *zkWhirData2.BlindingMerkleData,
		}
	}

	// 8. Parse interner and build matrices
	interner, err := ParseInterner(r1csData)
	if err != nil {
		return nil, nil, fmt.Errorf("parse interner: %w", err)
	}

	matrixA, matrixB, matrixC, err := buildR1CSMatrixCells(r1csData, interner)
	if err != nil {
		return nil, nil, fmt.Errorf("build matrices: %w", err)
	}

	// 9. Build circuit template and assignment (mirrors verifyCircuit)
	var protocolID [64]byte
	copy(protocolID[:], config.ProtocolID)
	var sessionIDBytes [32]byte
	copy(sessionIDBytes[:], config.SessionID)

	transcriptT := make([]uints.U8, len(config.NargString))
	contTranscript := make([]uints.U8, len(config.NargString))
	for i := range config.NargString {
		transcriptT[i] = uints.NewU8(config.NargString[i])
	}

	publicInputsContainer := PublicInputs{
		Values: make([]frontend.Variable, len(config.PublicInputs.Values)),
	}

	blindedMerkleTemplate := allocateZeroWhirMerkleData(*zkWhirData1.BlindedMerkleData)
	blindingMerkleTemplate := allocateZeroWhirMerkleData(*zkWhirData1.BlindingMerkleData)

	var blindedMerkleTemplate2, blindingMerkleTemplate2 whir.WhirMerkleData
	if dualData != nil {
		blindedMerkleTemplate2 = allocateZeroWhirMerkleData(dualData.BlindedMerkleData)
		blindingMerkleTemplate2 = allocateZeroWhirMerkleData(dualData.BlindingMerkleData)
	}

	circuit := &Circuit{
		ProtocolID:                   protocolID,
		SessionIDBytes:               sessionIDBytes,
		Transcript:                   contTranscript,
		LogNumConstraints:            config.LogNumConstraints,
		NumChallenges:                config.NumChallenges,
		ChallengeOffsets:             config.ChallengeOffsets,
		W1Size:                       config.W1Size,
		BlindingCommitmentWhirConfig: NewWhirParams(config.BlindingCommitmentWhirConfig),
		BlindedCommitmentWhirConfig:  NewWhirParams(config.BlindedCommitmentWhirConfig),
		PublicInputs:                 publicInputsContainer,
		BlindedMerkleData:            blindedMerkleTemplate,
		BlindingMerkleData:           blindingMerkleTemplate,
		BlindedMerkleData2:           blindedMerkleTemplate2,
		BlindingMerkleData2:          blindingMerkleTemplate2,
		MatrixA:                      matrixA,
		MatrixB:                      matrixB,
		MatrixC:                      matrixC,
	}

	var blindedMerkleAssign2, blindingMerkleAssign2 whir.WhirMerkleData
	if dualData != nil {
		blindedMerkleAssign2 = dualData.BlindedMerkleData
		blindingMerkleAssign2 = dualData.BlindingMerkleData
	}

	piValuesNative := make([]*big.Int, len(config.PublicInputs.Values))
	for i, v := range config.PublicInputs.Values {
		bi, ok := v.(*big.Int)
		if !ok {
			return nil, nil, fmt.Errorf("public input %d is not *big.Int (got %T)", i, v)
		}
		piValuesNative[i] = bi
	}
	publicInputsHashLE := nativePublicInputsHashBytes(piValuesNative)
	publicInputsHashBI := leBytesToNativeBigInt(publicInputsHashLE[:])

	assignment := &Circuit{
		ProtocolID:                   protocolID,
		SessionIDBytes:               sessionIDBytes,
		PublicInputsHash:             publicInputsHashBI,
		Transcript:                   transcriptT,
		LogNumConstraints:            config.LogNumConstraints,
		NumChallenges:                config.NumChallenges,
		ChallengeOffsets:             config.ChallengeOffsets,
		W1Size:                       config.W1Size,
		BlindingCommitmentWhirConfig: NewWhirParams(config.BlindingCommitmentWhirConfig),
		BlindedCommitmentWhirConfig:  NewWhirParams(config.BlindedCommitmentWhirConfig),
		PublicInputs:                 config.PublicInputs,
		BlindedMerkleData:            *zkWhirData1.BlindedMerkleData,
		BlindingMerkleData:           *zkWhirData1.BlindingMerkleData,
		BlindedMerkleData2:           blindedMerkleAssign2,
		BlindingMerkleData2:          blindingMerkleAssign2,
		MatrixA:                      matrixA,
		MatrixB:                      matrixB,
		MatrixC:                      matrixC,
	}

	return circuit, assignment, nil
}
