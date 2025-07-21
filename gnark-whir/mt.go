package main

import (
	"fmt"
	"log"
	"math/big"
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

	t_rand, sp_rand, savedValForSumcheck, err := SumcheckForR1CSIOP(api, arthur, circuit)
	if err != nil {
		return err
	}

	if err := FillInAndVerifyRootHash(0, api, uapi, sc, circuit, arthur); err != nil {
		return err
	}

	initialOODQueries, initialOODAnswers, err := FillInOODPointsAndAnswers(circuit.WHIRCircuitCol.CommittmentOODSamples, arthur)
	if err != nil {
		return err
	}

	initialCombinationRandomness, err := GenerateCombinationRandomness(api, arthur, circuit.WHIRCircuitCol.CommittmentOODSamples+len(circuit.LinearStatementEvaluations))
	if err != nil {
		return err
	}

	OODAnswersAndStatmentEvaluations := append(initialOODAnswers, circuit.LinearStatementEvaluations...)
	lastEval := utilities.DotProduct(api, initialCombinationRandomness, OODAnswersAndStatmentEvaluations)

	initialSumcheckFoldingRandomness, lastEval, err := runWhirSumcheckRounds(api, lastEval, arthur, circuit.WHIRCircuitCol.FoldingFactorArray[0], 3)
	if err != nil {
		return err
	}

	initialData := InitialSumcheckData{
		InitialOODQueries:            initialOODQueries,
		InitialCombinationRandomness: initialCombinationRandomness,
	}

	computedFold := computeFold(circuit.WHIRCircuitCol.Leaves[0], initialSumcheckFoldingRandomness, api)

	mainRoundData := generateEmptyMainRoundData(circuit)
	expDomainGenerator := utilities.Exponent(api, uapi, circuit.WHIRCircuitCol.StartingDomainBackingDomainGenerator, uints.NewU64(uint64(1<<circuit.WHIRCircuitCol.FoldingFactorArray[0])))
	domainSize := circuit.WHIRCircuitCol.DomainSize

	totalFoldingRandomness := initialSumcheckFoldingRandomness

	for r := range circuit.WHIRCircuitCol.ParamNRounds {
		if err = FillInAndVerifyRootHash(r+1, api, uapi, sc, circuit, arthur); err != nil {
			return err
		}

		var roundOODAnswers []frontend.Variable
		mainRoundData.OODPoints[r], roundOODAnswers, err = FillInOODPointsAndAnswers(circuit.WHIRCircuitCol.RoundParametersOODSamples[r], arthur)
		if err != nil {
			return err
		}
		mainRoundData.StirChallengesPoints[r], err = GenerateStirChallengePoints(api, arthur, circuit.WHIRCircuitCol.RoundParametersNumOfQueries[r], circuit.WHIRCircuitCol.LeafIndexes[r], domainSize, circuit, uapi, expDomainGenerator, r)
		if err != nil {
			return err
		}
		if err = RunPoW(api, sc, arthur, circuit.WHIRCircuitCol.PowBits[r]); err != nil {
			return err
		}

		mainRoundData.CombinationRandomness[r], err = GenerateCombinationRandomness(api, arthur, len(circuit.WHIRCircuitCol.LeafIndexes[r])+circuit.WHIRCircuitCol.RoundParametersOODSamples[r])
		if err != nil {
			return err
		}

		lastEval = api.Add(lastEval, calculateShiftValue(roundOODAnswers, mainRoundData.CombinationRandomness[r], computedFold, api))

		var roundFoldingRandomness []frontend.Variable
		roundFoldingRandomness, lastEval, err = runWhirSumcheckRounds(api, lastEval, arthur, circuit.WHIRCircuitCol.FoldingFactorArray[r], 3)
		if err != nil {
			return nil
		}

		computedFold = computeFold(circuit.WHIRCircuitCol.Leaves[r+1], roundFoldingRandomness, api)
		totalFoldingRandomness = append(totalFoldingRandomness, roundFoldingRandomness...)

		domainSize /= 2
		expDomainGenerator = api.Mul(expDomainGenerator, expDomainGenerator)
	}

	finalCoefficients, finalRandomnessPoints, err := generateFinalCoefficientsAndRandomnessPoints(api, arthur, circuit, uapi, sc, domainSize, expDomainGenerator)
	if err != nil {
		return err
	}

	finalEvaluations := utilities.UnivarPoly(api, finalCoefficients, finalRandomnessPoints)

	for foldIndex := range computedFold {
		api.AssertIsEqual(computedFold[foldIndex], finalEvaluations[foldIndex])
	}

	finalSumcheckRandomness, lastEval, err := runWhirSumcheckRounds(api, lastEval, arthur, circuit.WHIRCircuitCol.FinalSumcheckRounds, 3)
	if err != nil {
		return err
	}

	totalFoldingRandomness = append(totalFoldingRandomness, finalSumcheckRandomness...)

	if circuit.WHIRCircuitCol.FinalFoldingPowBits > 0 {
		_, _, err := utilities.PoW(api, sc, arthur, circuit.WHIRCircuitCol.FinalPowBits)
		if err != nil {
			return err
		}
	}

	evaluationOfVPoly := ComputeWPoly(
		api,
		circuit,
		initialData,
		mainRoundData,
		sp_rand,
		totalFoldingRandomness,
	)

	api.AssertIsEqual(
		lastEval,
		api.Mul(evaluationOfVPoly, utilities.MultivarPoly(finalCoefficients, finalSumcheckRandomness, api)),
	)

	x := api.Mul(api.Sub(api.Mul(circuit.LinearStatementEvaluations[0], circuit.LinearStatementEvaluations[1]), circuit.LinearStatementEvaluations[2]), calculateEQ(api, sp_rand, t_rand))
	api.AssertIsEqual(savedValForSumcheck, x)

	//

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

	// runSumcheckRounds(api, circuit.LinearStatementValuesAtPoints[0], arthur, circuit., 4);
	return nil
}

func verify_circuit(
	deferred []Fp256, cfg Config, merkle_paths []MultiPath[KeccakDigest],
	stir_answers [][][]Fp256, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, outputCcsPath string,
) {
	container_merkle := new_merkle(merkle_paths, stir_answers, true)
	merkle := new_merkle(merkle_paths, stir_answers, false)
	startingDomainGen, _ := new(big.Int).SetString(cfg.WHIRConfigCol.DomainGenerator, 10)
	mvParamsNumberOfVariables := cfg.WHIRConfigCol.NVars
	var foldingFactor []int
	var finalSumcheckRounds int

	if len(cfg.WHIRConfigCol.FoldingFactor) > 1 {
		foldingFactor = append(cfg.WHIRConfigCol.FoldingFactor, cfg.WHIRConfigCol.FoldingFactor[len(cfg.WHIRConfigCol.FoldingFactor)-1])
		finalSumcheckRounds = mvParamsNumberOfVariables % foldingFactor[len(foldingFactor)-1]
	} else {
		foldingFactor = []int{4}
		finalSumcheckRounds = mvParamsNumberOfVariables % 4
	}
	domainSize := (2 << mvParamsNumberOfVariables) * (1 << cfg.WHIRConfigCol.Rate) / 2
	oodSamples := cfg.WHIRConfigCol.OODSamples
	numOfQueries := cfg.WHIRConfigCol.NumQueries
	powBits := cfg.WHIRConfigCol.PowBits
	finalQueries := cfg.WHIRConfigCol.FinalQueries
	nRounds := cfg.WHIRConfigCol.NRounds

	transcriptT := make([]uints.U8, cfg.TranscriptLen)
	contTranscript := make([]uints.U8, cfg.TranscriptLen)

	for i := range cfg.Transcript {
		transcriptT[i] = uints.NewU8(cfg.Transcript[i])
		contTranscript[i] = uints.NewU8(cfg.Transcript[i])
	}

	linearStatementValuesAtPoints := make([]frontend.Variable, len(deferred))
	contLinearStatementValuesAtPoints := make([]frontend.Variable, len(deferred))

	linearStatementEvaluations := make([]frontend.Variable, len(cfg.StatementEvaluations))
	contLinearStatementEvaluations := make([]frontend.Variable, len(cfg.StatementEvaluations))
	for i := range len(deferred) {
		linearStatementValuesAtPoints[i] = typeConverters.LimbsToBigIntMod(deferred[i].Limbs)
		contLinearStatementValuesAtPoints[i] = typeConverters.LimbsToBigIntMod(deferred[i].Limbs)
		x, _ := new(big.Int).SetString(cfg.StatementEvaluations[i], 10)
		linearStatementEvaluations[i] = frontend.Variable(x)
		contLinearStatementEvaluations[i] = frontend.Variable(x)
	}

	whir_circuit_col := WHIRCircuit{
		ParamNRounds:                         nRounds,
		FoldingFactorArray:                   foldingFactor,
		RoundParametersOODSamples:            oodSamples,
		RoundParametersNumOfQueries:          numOfQueries,
		PowBits:                              powBits,
		FinalQueries:                         finalQueries,
		FinalPowBits:                         cfg.WHIRConfigCol.FinalPowBits,
		FinalFoldingPowBits:                  cfg.WHIRConfigCol.FinalFoldingPowBits,
		StartingDomainBackingDomainGenerator: startingDomainGen,
		DomainSize:                           domainSize,
		CommittmentOODSamples:                1,
		FinalSumcheckRounds:                  finalSumcheckRounds,
		MVParamsNumberOfVariables:            mvParamsNumberOfVariables,
		Leaves:                               container_merkle.totalLeaves,
		LeafIndexes:                          container_merkle.totalLeafIndexes,
		LeafSiblingHashes:                    container_merkle.totalLeafSiblingHashes,
		AuthPaths:                            container_merkle.totalAuthPath,
	}

	var circuit = Circuit{
		IO:                []byte(cfg.IOPattern),
		Transcript:        contTranscript,
		LogNumConstraints: cfg.LogNumConstraints,

		LinearStatementEvaluations:    contLinearStatementEvaluations,
		LinearStatementValuesAtPoints: contLinearStatementValuesAtPoints,
		WHIRCircuitCol:                whir_circuit_col,
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

	whir_circuit_assignment := WHIRCircuit{
		ParamNRounds:                         nRounds,
		FoldingFactorArray:                   foldingFactor,
		RoundParametersOODSamples:            oodSamples,
		RoundParametersNumOfQueries:          numOfQueries,
		PowBits:                              powBits,
		FinalQueries:                         finalQueries,
		FinalPowBits:                         cfg.WHIRConfigCol.FinalPowBits,
		FinalFoldingPowBits:                  cfg.WHIRConfigCol.FinalFoldingPowBits,
		StartingDomainBackingDomainGenerator: startingDomainGen,
		DomainSize:                           domainSize,
		CommittmentOODSamples:                1,
		FinalSumcheckRounds:                  finalSumcheckRounds,
		MVParamsNumberOfVariables:            mvParamsNumberOfVariables,
		Leaves:                               merkle.totalLeaves,
		LeafIndexes:                          merkle.totalLeafIndexes,
		LeafSiblingHashes:                    merkle.totalLeafSiblingHashes,
		AuthPaths:                            merkle.totalAuthPath,
	}

	assignment := Circuit{
		IO:                []byte(cfg.IOPattern),
		Transcript:        transcriptT,
		LogNumConstraints: cfg.LogNumConstraints,

		LinearStatementEvaluations:    linearStatementEvaluations,
		LinearStatementValuesAtPoints: linearStatementValuesAtPoints,
		WHIRCircuitCol:                whir_circuit_assignment,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, *pk, witness, backend.WithSolverOptions(solver.WithHints(utilities.IndexOf)))
	err = groth16.Verify(proof, *vk, publicWitness)
	if err != nil {
		fmt.Println(err)
	}
}
