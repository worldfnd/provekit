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

	initialSumcheckData, lastEval, initialSumcheckFoldingRandomness, err := initialSumcheck(api, circuit, arthur, uapi, sc)
	if err != nil {
		return err
	}

	computedFold := computeFold(circuit.Leaves[0], initialSumcheckFoldingRandomness, api)

	mainRoundData := generateEmptyMainRoundData(circuit)
	expDomainGenerator := utilities.Exponent(api, uapi, circuit.WHIRCircuitCol.StartingDomainBackingDomainGenerator, uints.NewU64(uint64(1<<circuit.WHIRCircuitCol.FoldingFactorArray[0])))
	domainSize := circuit.DomainSize

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
		mainRoundData.StirChallengesPoints[r], err = GenerateStirChallengePoints(api, arthur, circuit.WHIRCircuitCol.RoundParametersNumOfQueries[r], circuit.LeafIndexes[r], domainSize, circuit, uapi, expDomainGenerator, r)
		if err != nil {
			return err
		}
		if err = RunPoW(api, sc, arthur, circuit.WHIRCircuitCol.PowBits[r]); err != nil {
			return err
		}

		mainRoundData.CombinationRandomness[r], err = GenerateCombinationRandomness(api, arthur, len(circuit.LeafIndexes[r])+circuit.WHIRCircuitCol.RoundParametersOODSamples[r])
		if err != nil {
			return err
		}

		lastEval = api.Add(lastEval, calculateShiftValue(roundOODAnswers, mainRoundData.CombinationRandomness[r], computedFold, api))

		var roundFoldingRandomness []frontend.Variable
		roundFoldingRandomness, lastEval, err = runSumcheckRounds(api, lastEval, arthur, circuit.WHIRCircuitCol.FoldingFactorArray[r], 3)
		if err != nil {
			return nil
		}

		computedFold = computeFold(circuit.Leaves[r+1], roundFoldingRandomness, api)
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

	finalSumcheckRandomness, lastEval, err := runSumcheckRounds(api, lastEval, arthur, circuit.FinalSumcheckRounds, 3)
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
		initialSumcheckData,
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

	return nil
}

func verify_circuit(
	deferred []Fp256, cfg Config, merkle_paths []MultiPath[KeccakDigest],
	stir_answers [][][]Fp256, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, outputCcsPath string,
) {
	var totalAuthPath = make([][][][]uints.U8, len(merkle_paths))
	var totalLeaves = make([][][]frontend.Variable, len(merkle_paths))
	var totalLeafSiblingHashes = make([][][]uints.U8, len(merkle_paths))
	var totalLeafIndexes = make([][]uints.U64, len(merkle_paths))

	var containerTotalAuthPath = make([][][][]uints.U8, len(merkle_paths))
	var containerTotalLeaves = make([][][]frontend.Variable, len(merkle_paths))
	var containerTotalLeafSiblingHashes = make([][][]uints.U8, len(merkle_paths))
	var containerTotalLeafIndexes = make([][]uints.U64, len(merkle_paths))

	for i, merkle_path := range merkle_paths {
		var numOfLeavesProved = len(merkle_path.LeafIndexes)
		var treeHeight = len(merkle_path.AuthPathsSuffixes[0])

		totalAuthPath[i] = make([][][]uints.U8, numOfLeavesProved)
		containerTotalAuthPath[i] = make([][][]uints.U8, numOfLeavesProved)
		totalLeaves[i] = make([][]frontend.Variable, numOfLeavesProved)
		containerTotalLeaves[i] = make([][]frontend.Variable, numOfLeavesProved)
		totalLeafSiblingHashes[i] = make([][]uints.U8, numOfLeavesProved)
		containerTotalLeafSiblingHashes[i] = make([][]uints.U8, numOfLeavesProved)

		for j := range numOfLeavesProved {
			totalAuthPath[i][j] = make([][]uints.U8, treeHeight)
			containerTotalAuthPath[i][j] = make([][]uints.U8, treeHeight)

			for z := range treeHeight {
				totalAuthPath[i][j][z] = make([]uints.U8, 32)
				containerTotalAuthPath[i][j][z] = make([]uints.U8, 32)
			}
			totalLeaves[i][j] = make([]frontend.Variable, len(stir_answers[i][j]))
			containerTotalLeaves[i][j] = make([]frontend.Variable, len(stir_answers[i][j]))
			totalLeafSiblingHashes[i][j] = make([]uints.U8, 32)
			containerTotalLeafSiblingHashes[i][j] = make([]uints.U8, 32)
		}

		containerTotalLeafIndexes[i] = make([]uints.U64, numOfLeavesProved)

		var authPathsTemp = make([][]KeccakDigest, numOfLeavesProved)
		var prevPath = merkle_path.AuthPathsSuffixes[0]
		authPathsTemp[0] = utilities.Reverse(prevPath)

		for j := range totalAuthPath[i][0] {
			totalAuthPath[i][0][j] = uints.NewU8Array(authPathsTemp[0][j].KeccakDigest[:])
		}

		for j := 1; j < numOfLeavesProved; j++ {
			prevPath = utilities.PrefixDecodePath(prevPath, merkle_path.AuthPathsPrefixLengths[j], merkle_path.AuthPathsSuffixes[j])
			authPathsTemp[j] = utilities.Reverse(prevPath)
			for z := 0; z < treeHeight; z++ {
				totalAuthPath[i][j][z] = uints.NewU8Array(authPathsTemp[j][z].KeccakDigest[:])
			}
		}
		totalLeafIndexes[i] = make([]uints.U64, numOfLeavesProved)

		for z := range numOfLeavesProved {
			totalLeafSiblingHashes[i][z] = uints.NewU8Array(merkle_path.LeafSiblingHashes[z].KeccakDigest[:])
			totalLeafIndexes[i][z] = uints.NewU64(merkle_path.LeafIndexes[z])
			// fmt.Println(stir_answers[i][z])
			for j := range stir_answers[i][z] {
				input := stir_answers[i][z][j]
				// fmt.Println("===============")
				// fmt.Println(j)
				// fmt.Println(input.Limbs)
				// fmt.Println("===============")
				totalLeaves[i][z][j] = typeConverters.LimbsToBigIntMod(input.Limbs)
			}
		}
	}
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
	}

	var circuit = Circuit{
		IO:                            []byte(cfg.IOPattern),
		Transcript:                    contTranscript,
		InitialStatement:              true,
		CommittmentOODSamples:         1,
		DomainSize:                    domainSize,
		MVParamsNumberOfVariables:     mvParamsNumberOfVariables,
		FinalSumcheckRounds:           finalSumcheckRounds,
		StatementEvaluations:          0,
		LinearStatementEvaluations:    contLinearStatementEvaluations,
		LinearStatementValuesAtPoints: contLinearStatementValuesAtPoints,
		Leaves:                        containerTotalLeaves,
		LeafIndexes:                   containerTotalLeafIndexes,
		LeafSiblingHashes:             containerTotalLeafSiblingHashes,
		AuthPaths:                     containerTotalAuthPath,
		WHIRCircuitCol:                whir_circuit_col,
		LogNumConstraints:             cfg.LogNumConstraints,
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
		IO:                            []byte(cfg.IOPattern),
		Transcript:                    transcriptT,
		InitialStatement:              true,
		CommittmentOODSamples:         1,
		DomainSize:                    domainSize,
		FinalSumcheckRounds:           finalSumcheckRounds,
		MVParamsNumberOfVariables:     mvParamsNumberOfVariables,
		StatementEvaluations:          0,
		LinearStatementEvaluations:    linearStatementEvaluations,
		LinearStatementValuesAtPoints: linearStatementValuesAtPoints,
		Leaves:                        totalLeaves,
		LeafIndexes:                   totalLeafIndexes,
		LeafSiblingHashes:             totalLeafSiblingHashes,
		AuthPaths:                     totalAuthPath,
		WHIRCircuitCol:                whir_circuit_col,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, *pk, witness, backend.WithSolverOptions(solver.WithHints(utilities.IndexOf)))
	err = groth16.Verify(proof, *vk, publicWitness)
	if err != nil {
		fmt.Println(err)
	}
}
