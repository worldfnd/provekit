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

type Circuit struct {
	// Inputs
	LinearStatementValuesAtPoints []frontend.Variable
	LinearStatementEvaluations    []frontend.Variable
	LogNumConstraints             int
	LogNumVariables               int
	LogANumTerms                  int

	SpartanMerkle Merkle

	SparkASumcheckValueMerkle Merkle
	SparkASumcheckERXMerkle   Merkle
	SparkASumcheckERYMerkle   Merkle

	SparkRowwise MemoryCheckCircuits
	SparkColwise MemoryCheckCircuits

	WHIRParamsCol     WHIRParams
	WHIRParamsRow     WHIRParams
	WHIRParamsA       WHIRParams
	SumcheckLastFolds []frontend.Variable
	// Public Input
	IO         []byte
	Transcript []uints.U8 `gnark:",public"`
}

type MemoryCheckCircuits struct {
	FinalGPAFinalCTCMerkle Merkle
	RSGPAAddrMerkle        Merkle
	RSGPAValueMerkle       Merkle
	RSGPATimeStampMerkle   Merkle
	WSGPAAddrMerkle        Merkle
	WSGPAValueMerkle       Merkle
	WSGPATimeStampMerkle   Merkle
}

func (circuit *Circuit) Define(api frontend.API) error {
	sc, arthur, uapi, err := initializeComponents(api, circuit)
	if err != nil {
		return err
	}

	tRand := make([]frontend.Variable, circuit.LogNumConstraints)
	err = arthur.FillChallengeScalars(tRand)
	if err != nil {
		return err
	}

	spartanSumcheckRand, spartanSumcheckLastValue, err := runSumcheck(api, arthur, frontend.Variable(0), circuit.LogNumConstraints, 4)
	if err != nil {
		return err
	}

	if err := FillInAndVerifyRootHash(0, api, uapi, sc, circuit.SpartanMerkle, arthur); err != nil {
		return err
	}

	spartanInitialOODQueries, spartanInitialOODAnswers, err := FillInOODPointsAndAnswers(circuit.WHIRParamsCol.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}

	spartanWhirRand, err := runWhir(api, arthur, uapi, sc, circuit.SpartanMerkle, circuit.WHIRParamsCol, circuit.LinearStatementEvaluations, circuit.LinearStatementValuesAtPoints, []frontend.Variable{}, [][]frontend.Variable{}, spartanInitialOODQueries, spartanInitialOODAnswers)
	if err != nil {
		return err
	}

	x := api.Mul(api.Sub(api.Mul(circuit.LinearStatementEvaluations[0], circuit.LinearStatementEvaluations[1]), circuit.LinearStatementEvaluations[2]), calculateEQ(api, spartanSumcheckRand, tRand))
	api.AssertIsEqual(spartanSumcheckLastValue, x)

	rowRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(rowRootHash); err != nil {
		return err
	}

	rowOODQueries, rowOODAnswers, err := FillInOODPointsAndAnswers(circuit.WHIRParamsA.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}

	colRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(colRootHash); err != nil {
		return err
	}

	colOODQueries, colOODAnswers, err := FillInOODPointsAndAnswers(circuit.WHIRParamsA.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}

	valRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(valRootHash); err != nil {
		return err
	}

	valOODQueries, valOODAnswers, err := FillInOODPointsAndAnswers(circuit.WHIRParamsA.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}

	eRxRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(eRxRootHash); err != nil {
		return err
	}

	eRxOODQueries, eRxOODAnswers, err := FillInOODPointsAndAnswers(circuit.WHIRParamsA.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}
	eRyRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(eRyRootHash); err != nil {
		return err
	}

	eRyOODQueries, eRyOODAnswers, err := FillInOODPointsAndAnswers(circuit.WHIRParamsA.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}
	readTSRowRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(readTSRowRootHash); err != nil {
		return err
	}

	readTSRowOODQueries, readTSRowOODAnswers, err := FillInOODPointsAndAnswers(circuit.WHIRParamsA.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}
	readTSColRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(readTSColRootHash); err != nil {
		return err
	}

	readTSColOODQueries, readTSColOODAnswers, err := FillInOODPointsAndAnswers(circuit.WHIRParamsA.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}
	finalCTSRowRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(finalCTSRowRootHash); err != nil {
		return err
	}

	finalCTSRowOODPoints, finalCTSRowOODAnswers, err := FillInOODPointsAndAnswers(circuit.WHIRParamsCol.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}
	finalCTSColRootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(finalCTSColRootHash); err != nil {
		return err
	}

	finalCTSColOODPoints, finalCTSColOODAnswers, err := FillInOODPointsAndAnswers(circuit.WHIRParamsRow.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}

	sparkSumcheckFoldingRandomness, sparkSumcheckLastValue, err := runSumcheck(api, arthur, circuit.LinearStatementValuesAtPoints[0], circuit.LogANumTerms, 4)
	if err != nil {
		return err
	}

	api.AssertIsEqual(sparkSumcheckLastValue, api.Mul(circuit.SumcheckLastFolds[0], circuit.SumcheckLastFolds[1], circuit.SumcheckLastFolds[2]))

	_, err = runWhir(api, arthur, uapi, sc, circuit.SparkASumcheckValueMerkle, circuit.WHIRParamsA, []frontend.Variable{}, []frontend.Variable{}, []frontend.Variable{circuit.SumcheckLastFolds[0]}, [][]frontend.Variable{sparkSumcheckFoldingRandomness}, valOODQueries, valOODAnswers)
	if err != nil {
		return err
	}

	_, err = runWhir(api, arthur, uapi, sc, circuit.SparkASumcheckERXMerkle, circuit.WHIRParamsA, []frontend.Variable{}, []frontend.Variable{}, []frontend.Variable{circuit.SumcheckLastFolds[1]}, [][]frontend.Variable{sparkSumcheckFoldingRandomness}, eRxOODQueries, eRxOODAnswers)
	if err != nil {
		return err
	}

	_, err = runWhir(api, arthur, uapi, sc, circuit.SparkASumcheckERYMerkle, circuit.WHIRParamsA, []frontend.Variable{}, []frontend.Variable{}, []frontend.Variable{circuit.SumcheckLastFolds[2]}, [][]frontend.Variable{sparkSumcheckFoldingRandomness}, eRyOODQueries, eRyOODAnswers)
	if err != nil {
		return err
	}

	err = offlineMemoryCheck(
		api,
		uapi,
		sc,
		arthur,
		circuit.SparkRowwise,
		spartanSumcheckRand,
		circuit.LogNumConstraints,
		circuit.LogANumTerms,
		finalCTSRowOODPoints,
		finalCTSRowOODAnswers,
		rowOODQueries,
		rowOODAnswers,
		eRxOODQueries,
		eRxOODAnswers,
		readTSRowOODQueries,
		readTSRowOODAnswers,
		circuit.WHIRParamsRow,
		circuit.WHIRParamsA,
	)

	if err != nil {
		return err
	}

	err = offlineMemoryCheck(
		api,
		uapi,
		sc,
		arthur,
		circuit.SparkColwise,
		spartanWhirRand,
		circuit.LogNumVariables,
		circuit.LogANumTerms,
		finalCTSColOODPoints,
		finalCTSColOODAnswers,
		colOODQueries,
		colOODAnswers,
		eRyOODQueries,
		eRyOODAnswers,
		readTSColOODQueries,
		readTSColOODAnswers,
		circuit.WHIRParamsCol,
		circuit.WHIRParamsA,
	)

	if err != nil {
		return err
	}

	return nil
}

func verifyCircuit(
	deferred []Fp256,
	cfg Config,
	hints Hints,
	pk *groth16.ProvingKey,
	vk *groth16.VerifyingKey,
	outputCcsPath string,
	claimedEvaluations []Fp256,
	sumcheckLastFolds []Fp256,
) {
	transcriptT := make([]uints.U8, cfg.TranscriptLen)
	contTranscript := make([]uints.U8, cfg.TranscriptLen)

	for i := range cfg.Transcript {
		transcriptT[i] = uints.NewU8(cfg.Transcript[i])
	}

	linearStatementValuesAtPoints := make([]frontend.Variable, len(deferred))
	contLinearStatementValuesAtPoints := make([]frontend.Variable, len(deferred))

	linearStatementEvaluations := make([]frontend.Variable, len(claimedEvaluations))
	contLinearStatementEvaluations := make([]frontend.Variable, len(claimedEvaluations))
	for i := range len(deferred) {
		linearStatementValuesAtPoints[i] = typeConverters.LimbsToBigIntMod(deferred[i].Limbs)
		linearStatementEvaluations[i] = typeConverters.LimbsToBigIntMod(claimedEvaluations[i].Limbs)
	}

	sumcheckLastFoldsCircuit := make([]frontend.Variable, len(sumcheckLastFolds))
	contSumcheckLastFoldsCircuit := make([]frontend.Variable, len(sumcheckLastFolds))
	for i := range len(deferred) {
		sumcheckLastFoldsCircuit[i] = typeConverters.LimbsToBigIntMod(sumcheckLastFolds[i].Limbs)
	}

	var circuit = Circuit{
		IO:                []byte(cfg.IOPattern),
		Transcript:        contTranscript,
		LogNumConstraints: cfg.LogNumConstraints,
		LogNumVariables:   cfg.LogNumVariables,
		LogANumTerms:      cfg.LogANumTerms,

		LinearStatementEvaluations:    contLinearStatementEvaluations,
		LinearStatementValuesAtPoints: contLinearStatementValuesAtPoints,
		SumcheckLastFolds:             contSumcheckLastFoldsCircuit,

		SpartanMerkle:             newMerkle(hints.spartanHints, true),
		SparkASumcheckValueMerkle: newMerkle(hints.matrixA.SumcheckValHints, true),
		SparkASumcheckERXMerkle:   newMerkle(hints.matrixA.SumcheckERXHints, true),
		SparkASumcheckERYMerkle:   newMerkle(hints.matrixA.SumcheckERYHints, true),

		SparkRowwise: MemoryCheckCircuits{
			FinalGPAFinalCTCMerkle: newMerkle(hints.matrixA.rowwise.FinalGPAFinalCTRHints, true),
			RSGPAAddrMerkle:        newMerkle(hints.matrixA.rowwise.RSGPAAddrHints, true),
			RSGPAValueMerkle:       newMerkle(hints.matrixA.rowwise.RSGPAValueHints, true),
			RSGPATimeStampMerkle:   newMerkle(hints.matrixA.rowwise.RSGPATimeStampHints, true),
			WSGPAAddrMerkle:        newMerkle(hints.matrixA.rowwise.WSGPAAddrHints, true),
			WSGPAValueMerkle:       newMerkle(hints.matrixA.rowwise.WSGPAValueHints, true),
			WSGPATimeStampMerkle:   newMerkle(hints.matrixA.rowwise.WSGPATimeStampHints, true),
		},

		SparkColwise: MemoryCheckCircuits{
			FinalGPAFinalCTCMerkle: newMerkle(hints.matrixA.colwise.FinalGPAFinalCTRHints, true),
			RSGPAAddrMerkle:        newMerkle(hints.matrixA.colwise.RSGPAAddrHints, true),
			RSGPAValueMerkle:       newMerkle(hints.matrixA.colwise.RSGPAValueHints, true),
			RSGPATimeStampMerkle:   newMerkle(hints.matrixA.colwise.RSGPATimeStampHints, true),
			WSGPAAddrMerkle:        newMerkle(hints.matrixA.colwise.WSGPAAddrHints, true),
			WSGPAValueMerkle:       newMerkle(hints.matrixA.colwise.WSGPAValueHints, true),
			WSGPATimeStampMerkle:   newMerkle(hints.matrixA.colwise.WSGPATimeStampHints, true),
		},

		WHIRParamsCol: new_whir_params(cfg.WHIRConfigCol),
		WHIRParamsRow: new_whir_params(cfg.WHIRConfigRow),
		WHIRParamsA:   new_whir_params(cfg.WHIRConfigA),
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
		LogNumVariables:   cfg.LogNumVariables,
		LogANumTerms:      cfg.LogANumTerms,

		LinearStatementEvaluations:    linearStatementEvaluations,
		LinearStatementValuesAtPoints: linearStatementValuesAtPoints,
		SumcheckLastFolds:             sumcheckLastFoldsCircuit,

		SpartanMerkle:             newMerkle(hints.spartanHints, false),
		SparkASumcheckValueMerkle: newMerkle(hints.matrixA.SumcheckValHints, false),
		SparkASumcheckERXMerkle:   newMerkle(hints.matrixA.SumcheckERXHints, false),
		SparkASumcheckERYMerkle:   newMerkle(hints.matrixA.SumcheckERYHints, false),

		SparkRowwise: MemoryCheckCircuits{
			FinalGPAFinalCTCMerkle: newMerkle(hints.matrixA.rowwise.FinalGPAFinalCTRHints, false),
			RSGPAAddrMerkle:        newMerkle(hints.matrixA.rowwise.RSGPAAddrHints, false),
			RSGPAValueMerkle:       newMerkle(hints.matrixA.rowwise.RSGPAValueHints, false),
			RSGPATimeStampMerkle:   newMerkle(hints.matrixA.rowwise.RSGPATimeStampHints, false),
			WSGPAAddrMerkle:        newMerkle(hints.matrixA.rowwise.WSGPAAddrHints, false),
			WSGPAValueMerkle:       newMerkle(hints.matrixA.rowwise.WSGPAValueHints, false),
			WSGPATimeStampMerkle:   newMerkle(hints.matrixA.rowwise.WSGPATimeStampHints, false),
		},

		SparkColwise: MemoryCheckCircuits{
			FinalGPAFinalCTCMerkle: newMerkle(hints.matrixA.colwise.FinalGPAFinalCTRHints, false),
			RSGPAAddrMerkle:        newMerkle(hints.matrixA.colwise.RSGPAAddrHints, false),
			RSGPAValueMerkle:       newMerkle(hints.matrixA.colwise.RSGPAValueHints, false),
			RSGPATimeStampMerkle:   newMerkle(hints.matrixA.colwise.RSGPATimeStampHints, false),
			WSGPAAddrMerkle:        newMerkle(hints.matrixA.colwise.WSGPAAddrHints, false),
			WSGPAValueMerkle:       newMerkle(hints.matrixA.colwise.WSGPAValueHints, false),
			WSGPATimeStampMerkle:   newMerkle(hints.matrixA.colwise.WSGPATimeStampHints, false),
		},

		WHIRParamsCol: new_whir_params(cfg.WHIRConfigCol),
		WHIRParamsRow: new_whir_params(cfg.WHIRConfigRow),
		WHIRParamsA:   new_whir_params(cfg.WHIRConfigA),
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, *pk, witness, backend.WithSolverOptions(solver.WithHints(utilities.IndexOf)))
	err = groth16.Verify(proof, *vk, publicWitness)
	if err != nil {
		fmt.Println(err)
	}
}
