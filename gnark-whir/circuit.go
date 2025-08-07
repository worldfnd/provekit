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

type SparkMatrixMerkle struct {
	SumcheckValueMerkle Merkle
	SumcheckERXMerkle   Merkle
	SumcheckERYMerkle   Merkle

	Rowwise MemoryCheckCircuits
	Colwise MemoryCheckCircuits
}

type Circuit struct {
	// Inputs
	LinearStatementValuesAtPoints []frontend.Variable
	LinearStatementEvaluations    []frontend.Variable
	LogNumConstraints             int
	LogNumVariables               int
	LogANumTerms                  int
	LogBNumTerms                  int
	LogCNumTerms                  int

	SpartanMerkle Merkle

	MatrixA SparkMatrixMerkle
	MatrixB SparkMatrixMerkle
	MatrixC SparkMatrixMerkle

	WHIRParamsCol      WHIRParams
	WHIRParamsRow      WHIRParams
	WHIRParamsA        WHIRParams
	WHIRParamsB        WHIRParams
	WHIRParamsC        WHIRParams
	SumcheckLastFoldsA []frontend.Variable
	SumcheckLastFoldsB []frontend.Variable
	SumcheckLastFoldsC []frontend.Variable
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

	err = runSpark(
		arthur,
		circuit.WHIRParamsA,
		circuit.LogANumTerms,
		circuit.LogNumConstraints,
		circuit.LogNumVariables,
		circuit.WHIRParamsRow,
		circuit.WHIRParamsCol,
		circuit.LinearStatementValuesAtPoints[0],
		api,
		uapi,
		sc,
		circuit.MatrixA,
		spartanSumcheckRand,
		spartanWhirRand,
		circuit.SumcheckLastFoldsA,
	)

	if err != nil {
		return err
	}

	err = runSpark(
		arthur,
		circuit.WHIRParamsB,
		circuit.LogBNumTerms,
		circuit.LogNumConstraints,
		circuit.LogNumVariables,
		circuit.WHIRParamsRow,
		circuit.WHIRParamsCol,
		circuit.LinearStatementValuesAtPoints[1],
		api,
		uapi,
		sc,
		circuit.MatrixB,
		spartanSumcheckRand,
		spartanWhirRand,
		circuit.SumcheckLastFoldsB,
	)

	if err != nil {
		return err
	}

	err = runSpark(
		arthur,
		circuit.WHIRParamsC,
		circuit.LogCNumTerms,
		circuit.LogNumConstraints,
		circuit.LogNumVariables,
		circuit.WHIRParamsRow,
		circuit.WHIRParamsCol,
		circuit.LinearStatementValuesAtPoints[2],
		api,
		uapi,
		sc,
		circuit.MatrixC,
		spartanSumcheckRand,
		spartanWhirRand,
		circuit.SumcheckLastFoldsC,
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

	sumcheckLastFoldsACircuit := make([]frontend.Variable, 3)
	contSumcheckLastFoldsACircuit := make([]frontend.Variable, 3)
	sumcheckLastFoldsACircuit[0] = typeConverters.LimbsToBigIntMod(sumcheckLastFolds[0].Limbs)
	sumcheckLastFoldsACircuit[1] = typeConverters.LimbsToBigIntMod(sumcheckLastFolds[1].Limbs)
	sumcheckLastFoldsACircuit[2] = typeConverters.LimbsToBigIntMod(sumcheckLastFolds[2].Limbs)

	sumcheckLastFoldsBCircuit := make([]frontend.Variable, 3)
	contSumcheckLastFoldsBCircuit := make([]frontend.Variable, 3)
	sumcheckLastFoldsBCircuit[0] = typeConverters.LimbsToBigIntMod(sumcheckLastFolds[3].Limbs)
	sumcheckLastFoldsBCircuit[1] = typeConverters.LimbsToBigIntMod(sumcheckLastFolds[4].Limbs)
	sumcheckLastFoldsBCircuit[2] = typeConverters.LimbsToBigIntMod(sumcheckLastFolds[5].Limbs)

	sumcheckLastFoldsCCircuit := make([]frontend.Variable, 3)
	contSumcheckLastFoldsCCircuit := make([]frontend.Variable, 3)
	sumcheckLastFoldsCCircuit[0] = typeConverters.LimbsToBigIntMod(sumcheckLastFolds[6].Limbs)
	sumcheckLastFoldsCCircuit[1] = typeConverters.LimbsToBigIntMod(sumcheckLastFolds[7].Limbs)
	sumcheckLastFoldsCCircuit[2] = typeConverters.LimbsToBigIntMod(sumcheckLastFolds[8].Limbs)

	var circuit = Circuit{
		IO:                []byte(cfg.IOPattern),
		Transcript:        contTranscript,
		LogNumConstraints: cfg.LogNumConstraints,
		LogNumVariables:   cfg.LogNumVariables,
		LogANumTerms:      cfg.LogANumTerms,
		LogBNumTerms:      cfg.LogBNumTerms,
		LogCNumTerms:      cfg.LogCNumTerms,

		LinearStatementEvaluations:    contLinearStatementEvaluations,
		LinearStatementValuesAtPoints: contLinearStatementValuesAtPoints,
		SumcheckLastFoldsA:            contSumcheckLastFoldsACircuit,
		SumcheckLastFoldsB:            contSumcheckLastFoldsBCircuit,
		SumcheckLastFoldsC:            contSumcheckLastFoldsCCircuit,

		SpartanMerkle: newMerkle(hints.spartanHints, true),

		MatrixA: SparkMatrixMerkle{
			SumcheckValueMerkle: newMerkle(hints.matrixA.SumcheckValHints, true),
			SumcheckERXMerkle:   newMerkle(hints.matrixA.SumcheckERXHints, true),
			SumcheckERYMerkle:   newMerkle(hints.matrixA.SumcheckERYHints, true),

			Rowwise: MemoryCheckCircuits{
				FinalGPAFinalCTCMerkle: newMerkle(hints.matrixA.rowwise.FinalGPAFinalCTRHints, true),
				RSGPAAddrMerkle:        newMerkle(hints.matrixA.rowwise.RSGPAAddrHints, true),
				RSGPAValueMerkle:       newMerkle(hints.matrixA.rowwise.RSGPAValueHints, true),
				RSGPATimeStampMerkle:   newMerkle(hints.matrixA.rowwise.RSGPATimeStampHints, true),
				WSGPAAddrMerkle:        newMerkle(hints.matrixA.rowwise.WSGPAAddrHints, true),
				WSGPAValueMerkle:       newMerkle(hints.matrixA.rowwise.WSGPAValueHints, true),
				WSGPATimeStampMerkle:   newMerkle(hints.matrixA.rowwise.WSGPATimeStampHints, true),
			},

			Colwise: MemoryCheckCircuits{
				FinalGPAFinalCTCMerkle: newMerkle(hints.matrixA.colwise.FinalGPAFinalCTRHints, true),
				RSGPAAddrMerkle:        newMerkle(hints.matrixA.colwise.RSGPAAddrHints, true),
				RSGPAValueMerkle:       newMerkle(hints.matrixA.colwise.RSGPAValueHints, true),
				RSGPATimeStampMerkle:   newMerkle(hints.matrixA.colwise.RSGPATimeStampHints, true),
				WSGPAAddrMerkle:        newMerkle(hints.matrixA.colwise.WSGPAAddrHints, true),
				WSGPAValueMerkle:       newMerkle(hints.matrixA.colwise.WSGPAValueHints, true),
				WSGPATimeStampMerkle:   newMerkle(hints.matrixA.colwise.WSGPATimeStampHints, true),
			},
		},

		MatrixB: SparkMatrixMerkle{
			SumcheckValueMerkle: newMerkle(hints.matrixB.SumcheckValHints, true),
			SumcheckERXMerkle:   newMerkle(hints.matrixB.SumcheckERXHints, true),
			SumcheckERYMerkle:   newMerkle(hints.matrixB.SumcheckERYHints, true),

			Rowwise: MemoryCheckCircuits{
				FinalGPAFinalCTCMerkle: newMerkle(hints.matrixB.rowwise.FinalGPAFinalCTRHints, true),
				RSGPAAddrMerkle:        newMerkle(hints.matrixB.rowwise.RSGPAAddrHints, true),
				RSGPAValueMerkle:       newMerkle(hints.matrixB.rowwise.RSGPAValueHints, true),
				RSGPATimeStampMerkle:   newMerkle(hints.matrixB.rowwise.RSGPATimeStampHints, true),
				WSGPAAddrMerkle:        newMerkle(hints.matrixB.rowwise.WSGPAAddrHints, true),
				WSGPAValueMerkle:       newMerkle(hints.matrixB.rowwise.WSGPAValueHints, true),
				WSGPATimeStampMerkle:   newMerkle(hints.matrixB.rowwise.WSGPATimeStampHints, true),
			},

			Colwise: MemoryCheckCircuits{
				FinalGPAFinalCTCMerkle: newMerkle(hints.matrixB.colwise.FinalGPAFinalCTRHints, true),
				RSGPAAddrMerkle:        newMerkle(hints.matrixB.colwise.RSGPAAddrHints, true),
				RSGPAValueMerkle:       newMerkle(hints.matrixB.colwise.RSGPAValueHints, true),
				RSGPATimeStampMerkle:   newMerkle(hints.matrixB.colwise.RSGPATimeStampHints, true),
				WSGPAAddrMerkle:        newMerkle(hints.matrixB.colwise.WSGPAAddrHints, true),
				WSGPAValueMerkle:       newMerkle(hints.matrixB.colwise.WSGPAValueHints, true),
				WSGPATimeStampMerkle:   newMerkle(hints.matrixB.colwise.WSGPATimeStampHints, true),
			},
		},

		MatrixC: SparkMatrixMerkle{
			SumcheckValueMerkle: newMerkle(hints.matrixC.SumcheckValHints, true),
			SumcheckERXMerkle:   newMerkle(hints.matrixC.SumcheckERXHints, true),
			SumcheckERYMerkle:   newMerkle(hints.matrixC.SumcheckERYHints, true),

			Rowwise: MemoryCheckCircuits{
				FinalGPAFinalCTCMerkle: newMerkle(hints.matrixC.rowwise.FinalGPAFinalCTRHints, true),
				RSGPAAddrMerkle:        newMerkle(hints.matrixC.rowwise.RSGPAAddrHints, true),
				RSGPAValueMerkle:       newMerkle(hints.matrixC.rowwise.RSGPAValueHints, true),
				RSGPATimeStampMerkle:   newMerkle(hints.matrixC.rowwise.RSGPATimeStampHints, true),
				WSGPAAddrMerkle:        newMerkle(hints.matrixC.rowwise.WSGPAAddrHints, true),
				WSGPAValueMerkle:       newMerkle(hints.matrixC.rowwise.WSGPAValueHints, true),
				WSGPATimeStampMerkle:   newMerkle(hints.matrixC.rowwise.WSGPATimeStampHints, true),
			},

			Colwise: MemoryCheckCircuits{
				FinalGPAFinalCTCMerkle: newMerkle(hints.matrixC.colwise.FinalGPAFinalCTRHints, true),
				RSGPAAddrMerkle:        newMerkle(hints.matrixC.colwise.RSGPAAddrHints, true),
				RSGPAValueMerkle:       newMerkle(hints.matrixC.colwise.RSGPAValueHints, true),
				RSGPATimeStampMerkle:   newMerkle(hints.matrixC.colwise.RSGPATimeStampHints, true),
				WSGPAAddrMerkle:        newMerkle(hints.matrixC.colwise.WSGPAAddrHints, true),
				WSGPAValueMerkle:       newMerkle(hints.matrixC.colwise.WSGPAValueHints, true),
				WSGPATimeStampMerkle:   newMerkle(hints.matrixC.colwise.WSGPATimeStampHints, true),
			},
		},

		WHIRParamsCol: new_whir_params(cfg.WHIRConfigCol),
		WHIRParamsRow: new_whir_params(cfg.WHIRConfigRow),
		WHIRParamsA:   new_whir_params(cfg.WHIRConfigA),
		WHIRParamsB:   new_whir_params(cfg.WHIRConfigB),
		WHIRParamsC:   new_whir_params(cfg.WHIRConfigC),
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
		LogBNumTerms:      cfg.LogBNumTerms,
		LogCNumTerms:      cfg.LogCNumTerms,

		LinearStatementEvaluations:    linearStatementEvaluations,
		LinearStatementValuesAtPoints: linearStatementValuesAtPoints,
		SumcheckLastFoldsA:            sumcheckLastFoldsACircuit,
		SumcheckLastFoldsB:            sumcheckLastFoldsBCircuit,
		SumcheckLastFoldsC:            sumcheckLastFoldsCCircuit,

		MatrixA: SparkMatrixMerkle{
			SumcheckValueMerkle: newMerkle(hints.matrixA.SumcheckValHints, false),
			SumcheckERXMerkle:   newMerkle(hints.matrixA.SumcheckERXHints, false),
			SumcheckERYMerkle:   newMerkle(hints.matrixA.SumcheckERYHints, false),

			Rowwise: MemoryCheckCircuits{
				FinalGPAFinalCTCMerkle: newMerkle(hints.matrixA.rowwise.FinalGPAFinalCTRHints, false),
				RSGPAAddrMerkle:        newMerkle(hints.matrixA.rowwise.RSGPAAddrHints, false),
				RSGPAValueMerkle:       newMerkle(hints.matrixA.rowwise.RSGPAValueHints, false),
				RSGPATimeStampMerkle:   newMerkle(hints.matrixA.rowwise.RSGPATimeStampHints, false),
				WSGPAAddrMerkle:        newMerkle(hints.matrixA.rowwise.WSGPAAddrHints, false),
				WSGPAValueMerkle:       newMerkle(hints.matrixA.rowwise.WSGPAValueHints, false),
				WSGPATimeStampMerkle:   newMerkle(hints.matrixA.rowwise.WSGPATimeStampHints, false),
			},

			Colwise: MemoryCheckCircuits{
				FinalGPAFinalCTCMerkle: newMerkle(hints.matrixA.colwise.FinalGPAFinalCTRHints, false),
				RSGPAAddrMerkle:        newMerkle(hints.matrixA.colwise.RSGPAAddrHints, false),
				RSGPAValueMerkle:       newMerkle(hints.matrixA.colwise.RSGPAValueHints, false),
				RSGPATimeStampMerkle:   newMerkle(hints.matrixA.colwise.RSGPATimeStampHints, false),
				WSGPAAddrMerkle:        newMerkle(hints.matrixA.colwise.WSGPAAddrHints, false),
				WSGPAValueMerkle:       newMerkle(hints.matrixA.colwise.WSGPAValueHints, false),
				WSGPATimeStampMerkle:   newMerkle(hints.matrixA.colwise.WSGPATimeStampHints, false),
			},
		},

		MatrixB: SparkMatrixMerkle{
			SumcheckValueMerkle: newMerkle(hints.matrixB.SumcheckValHints, false),
			SumcheckERXMerkle:   newMerkle(hints.matrixB.SumcheckERXHints, false),
			SumcheckERYMerkle:   newMerkle(hints.matrixB.SumcheckERYHints, false),

			Rowwise: MemoryCheckCircuits{
				FinalGPAFinalCTCMerkle: newMerkle(hints.matrixB.rowwise.FinalGPAFinalCTRHints, false),
				RSGPAAddrMerkle:        newMerkle(hints.matrixB.rowwise.RSGPAAddrHints, false),
				RSGPAValueMerkle:       newMerkle(hints.matrixB.rowwise.RSGPAValueHints, false),
				RSGPATimeStampMerkle:   newMerkle(hints.matrixB.rowwise.RSGPATimeStampHints, false),
				WSGPAAddrMerkle:        newMerkle(hints.matrixB.rowwise.WSGPAAddrHints, false),
				WSGPAValueMerkle:       newMerkle(hints.matrixB.rowwise.WSGPAValueHints, false),
				WSGPATimeStampMerkle:   newMerkle(hints.matrixB.rowwise.WSGPATimeStampHints, false),
			},

			Colwise: MemoryCheckCircuits{
				FinalGPAFinalCTCMerkle: newMerkle(hints.matrixB.colwise.FinalGPAFinalCTRHints, false),
				RSGPAAddrMerkle:        newMerkle(hints.matrixB.colwise.RSGPAAddrHints, false),
				RSGPAValueMerkle:       newMerkle(hints.matrixB.colwise.RSGPAValueHints, false),
				RSGPATimeStampMerkle:   newMerkle(hints.matrixB.colwise.RSGPATimeStampHints, false),
				WSGPAAddrMerkle:        newMerkle(hints.matrixB.colwise.WSGPAAddrHints, false),
				WSGPAValueMerkle:       newMerkle(hints.matrixB.colwise.WSGPAValueHints, false),
				WSGPATimeStampMerkle:   newMerkle(hints.matrixB.colwise.WSGPATimeStampHints, false),
			},
		},

		MatrixC: SparkMatrixMerkle{
			SumcheckValueMerkle: newMerkle(hints.matrixC.SumcheckValHints, false),
			SumcheckERXMerkle:   newMerkle(hints.matrixC.SumcheckERXHints, false),
			SumcheckERYMerkle:   newMerkle(hints.matrixC.SumcheckERYHints, false),

			Rowwise: MemoryCheckCircuits{
				FinalGPAFinalCTCMerkle: newMerkle(hints.matrixC.rowwise.FinalGPAFinalCTRHints, false),
				RSGPAAddrMerkle:        newMerkle(hints.matrixC.rowwise.RSGPAAddrHints, false),
				RSGPAValueMerkle:       newMerkle(hints.matrixC.rowwise.RSGPAValueHints, false),
				RSGPATimeStampMerkle:   newMerkle(hints.matrixC.rowwise.RSGPATimeStampHints, false),
				WSGPAAddrMerkle:        newMerkle(hints.matrixC.rowwise.WSGPAAddrHints, false),
				WSGPAValueMerkle:       newMerkle(hints.matrixC.rowwise.WSGPAValueHints, false),
				WSGPATimeStampMerkle:   newMerkle(hints.matrixC.rowwise.WSGPATimeStampHints, false),
			},

			Colwise: MemoryCheckCircuits{
				FinalGPAFinalCTCMerkle: newMerkle(hints.matrixC.colwise.FinalGPAFinalCTRHints, false),
				RSGPAAddrMerkle:        newMerkle(hints.matrixC.colwise.RSGPAAddrHints, false),
				RSGPAValueMerkle:       newMerkle(hints.matrixC.colwise.RSGPAValueHints, false),
				RSGPATimeStampMerkle:   newMerkle(hints.matrixC.colwise.RSGPATimeStampHints, false),
				WSGPAAddrMerkle:        newMerkle(hints.matrixC.colwise.WSGPAAddrHints, false),
				WSGPAValueMerkle:       newMerkle(hints.matrixC.colwise.WSGPAValueHints, false),
				WSGPATimeStampMerkle:   newMerkle(hints.matrixC.colwise.WSGPATimeStampHints, false),
			},
		},

		WHIRParamsCol: new_whir_params(cfg.WHIRConfigCol),
		WHIRParamsRow: new_whir_params(cfg.WHIRConfigRow),
		WHIRParamsA:   new_whir_params(cfg.WHIRConfigA),
		WHIRParamsB:   new_whir_params(cfg.WHIRConfigB),
		WHIRParamsC:   new_whir_params(cfg.WHIRConfigC),
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, *pk, witness, backend.WithSolverOptions(solver.WithHints(utilities.IndexOf)))
	err = groth16.Verify(proof, *vk, publicWitness)
	if err != nil {
		fmt.Println(err)
	}
}
