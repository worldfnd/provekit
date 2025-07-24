package main

import (
	"fmt"
	"log"
	"os"

	"reilabs/whir-verifier-circuit/typeConverters"
	"reilabs/whir-verifier-circuit/utilities"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
)

func (circuit *Circuit) Define(api frontend.API) error {
	sc, arthur, uapi, err := initializeComponents(api, circuit)
	if err != nil {
		return err
	}

	t_rand := make([]frontend.Variable, circuit.LogNumConstraints)
	err = arthur.FillChallengeScalars(t_rand)
	if err != nil {
		return err
	}

	spartan_sumcheck_rand, spartan_sumcheck_last_value, err := runSumcheck(api, arthur, frontend.Variable(0), circuit.WHIRCircuitCol.MVParamsNumberOfVariables, 4)
	if err != nil {
		return err
	}

	err = run_whir(api, arthur, uapi, sc, circuit.WHIRCircuitCol, circuit.LinearStatementEvaluations, circuit.LinearStatementValuesAtPoints)
	if err != nil {
		return err
	}

	x := api.Mul(api.Sub(api.Mul(circuit.LinearStatementEvaluations[0], circuit.LinearStatementEvaluations[1]), circuit.LinearStatementEvaluations[2]), calculateEQ(api, spartan_sumcheck_rand, t_rand))
	api.AssertIsEqual(spartan_sumcheck_last_value, x)

	rowRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(rowRootHash); err != nil {
		return err
	}

	_, _, err = FillInOODPointsAndAnswers(circuit.WHIRCircuitCol.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}

	colRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(colRootHash); err != nil {
		return err
	}

	_, _, err = FillInOODPointsAndAnswers(circuit.WHIRCircuitCol.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}

	valRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(valRootHash); err != nil {
		return err
	}

	_, _, err = FillInOODPointsAndAnswers(circuit.WHIRCircuitCol.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}

	e_rxRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(e_rxRootHash); err != nil {
		return err
	}

	_, _, err = FillInOODPointsAndAnswers(circuit.WHIRCircuitCol.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}
	e_ryRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(e_ryRootHash); err != nil {
		return err
	}

	_, _, err = FillInOODPointsAndAnswers(circuit.WHIRCircuitCol.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}
	readTSRowRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(readTSRowRootHash); err != nil {
		return err
	}

	_, _, err = FillInOODPointsAndAnswers(circuit.WHIRCircuitCol.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}
	readTSColRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(readTSColRootHash); err != nil {
		return err
	}

	_, _, err = FillInOODPointsAndAnswers(circuit.WHIRCircuitCol.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}
	finalCTSRowRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(finalCTSRowRootHash); err != nil {
		return err
	}

	_, _, err = FillInOODPointsAndAnswers(circuit.WHIRCircuitCol.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}
	finalCTSColRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(finalCTSColRootHash); err != nil {
		return err
	}

	_, _, err = FillInOODPointsAndAnswers(circuit.WHIRCircuitCol.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}

	runSumcheck(api, arthur, circuit.LinearStatementValuesAtPoints[0], circuit.WHIRCircuitA.MVParamsNumberOfVariables, 4)
	return nil
}

func verify_circuit(
	deferred []Fp256, cfg Config, hints Hints, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, outputCcsPath string, claimed_evalutations []Fp256,
) {
	container_merkle_col := new_merkle(hints.col_hints, true)
	merkle_col := new_merkle(hints.col_hints, false)
	whir_params_col := new_whir_params(cfg.WHIRConfigCol)

	container_merkle_a := new_merkle(hints.a_hints, true)
	merkle_a := new_merkle(hints.a_hints, false)
	whir_params_a := new_whir_params(cfg.WHIRConfigA)

	transcriptT := make([]uints.U8, cfg.TranscriptLen)
	contTranscript := make([]uints.U8, cfg.TranscriptLen)

	for i := range cfg.Transcript {
		transcriptT[i] = uints.NewU8(cfg.Transcript[i])
	}

	linearStatementValuesAtPoints := make([]frontend.Variable, len(deferred))
	contLinearStatementValuesAtPoints := make([]frontend.Variable, len(deferred))

	linearStatementEvaluations := make([]frontend.Variable, len(claimed_evalutations))
	contLinearStatementEvaluations := make([]frontend.Variable, len(claimed_evalutations))
	for i := range len(deferred) {
		linearStatementValuesAtPoints[i] = typeConverters.LimbsToBigIntMod(deferred[i].Limbs)
		linearStatementEvaluations[i] = typeConverters.LimbsToBigIntMod(claimed_evalutations[i].Limbs)
	}

	var circuit = Circuit{
		IO:                []byte(cfg.IOPattern),
		Transcript:        contTranscript,
		LogNumConstraints: cfg.LogNumConstraints,

		LinearStatementEvaluations:    contLinearStatementEvaluations,
		LinearStatementValuesAtPoints: contLinearStatementValuesAtPoints,
		WHIRCircuitCol:                new_whir_circuit(cfg.WHIRConfigCol, whir_params_col, container_merkle_col),
		WHIRCircuitA:                  new_whir_circuit(cfg.WHIRConfigA, whir_params_a, container_merkle_a),
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("Failed to compile circuit: %v", err)
	}
	if outputCcsPath != "" {
		ccsFile, err := os.Create(outputCcsPath)
		if err != nil {
			log.Printf("Cannot create ccs file %s: %v", outputCcsPath, err)
		} else {
			_, err = ccs.WriteTo(ccsFile)
			if err != nil {
				log.Printf("Cannot write ccs file %s: %v", outputCcsPath, err)
			}
		}
		log.Printf("ccs written to %s", outputCcsPath)
	}

	if pk == nil || vk == nil {
		log.Printf("PK/VK not provided, generating new keys unsafely. Consider providing keys from an MPC ceremony.")
		unsafePk, unsafeVk, err := groth16.Setup(ccs)
		if err != nil {
			log.Fatalf("Failed to setup groth16: %v", err)
		}
		pk = &unsafePk
		vk = &unsafeVk
	}

	assignment := Circuit{
		IO:                []byte(cfg.IOPattern),
		Transcript:        transcriptT,
		LogNumConstraints: cfg.LogNumConstraints,

		LinearStatementEvaluations:    linearStatementEvaluations,
		LinearStatementValuesAtPoints: linearStatementValuesAtPoints,
		WHIRCircuitCol:                new_whir_circuit(cfg.WHIRConfigCol, whir_params_col, merkle_col),
		WHIRCircuitA:                  new_whir_circuit(cfg.WHIRConfigA, whir_params_a, merkle_a),
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, *pk, witness, backend.WithSolverOptions(solver.WithHints(utilities.IndexOf)))
	err = groth16.Verify(proof, *vk, publicWitness)
	if err != nil {
		fmt.Println(err)
	}
}
