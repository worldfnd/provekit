package main

import (
	"math/big"
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
	expDomainGenerator := utilities.Exponent(api, uapi, circuit.StartingDomainBackingDomainGenerator, uints.NewU64(uint64(1<<circuit.FoldingFactorArray[0])))
	domainSize := circuit.DomainSize

	totalFoldingRandomness := initialSumcheckFoldingRandomness

	for r := range circuit.RoundParametersOODSamples {
		if err = FillInAndVerifyRootHash(r+1, api, uapi, sc, circuit, arthur); err != nil {
			return err
		}

		roundOODAnswers := []frontend.Variable{}
		mainRoundData.OODPoints[r], roundOODAnswers, err = FillInOODPointsAndAnswers(circuit.RoundParametersOODSamples[r], arthur)
		if err != nil {
			return err
		}
		mainRoundData.StirChallengesPoints[r], err = GenerateStirChallengePoints(api, arthur, circuit.RoundParametersNumOfQueries[r], circuit.LeafIndexes[r], domainSize, circuit, uapi, expDomainGenerator, r)
		if err != nil {
			return err
		}
		if err = RunPoW(api, sc, arthur, circuit.PowBits[r]); err != nil {
			return err
		}

		mainRoundData.CombinationRandomness[r], err = GenerateCombinationRandomness(api, arthur, len(circuit.LeafIndexes[r])+circuit.RoundParametersOODSamples[r])
		if err != nil {
			return err
		}

		lastEval = api.Add(lastEval, calculateShiftValue(roundOODAnswers, mainRoundData.CombinationRandomness[r], computedFold, api))

		roundFoldingRandomness := []frontend.Variable{}
		roundFoldingRandomness, lastEval, err = runSumcheckRounds(api, lastEval, arthur, circuit.FoldingFactorArray[r], 3)
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

	if circuit.FinalFoldingPowBits > 0 {
		_, _, err := utilities.PoW(api, sc, arthur, circuit.FinalFoldingPowBits)
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

func verify_circuit(proof_arg ProofObject, cfg Config, internedR1CS R1CS, interner Interner) {
	proofs := proof_arg.MerklePaths
	var totalAuthPath = make([][][][]uints.U8, len(proofs))
	var totalLeaves = make([][][]frontend.Variable, len(proofs))
	var totalLeafSiblingHashes = make([][][]uints.U8, len(proofs))
	var totalLeafIndexes = make([][]uints.U64, len(proofs))

	var containerTotalAuthPath = make([][][][]uints.U8, len(proofs))
	var containerTotalLeaves = make([][][]frontend.Variable, len(proofs))
	var containerTotalLeafSiblingHashes = make([][][]uints.U8, len(proofs))
	var containerTotalLeafIndexes = make([][]uints.U64, len(proofs))

	for i := range proofs {
		var numOfLeavesProved = len(proofs[i].A.LeafIndexes)
		var treeHeight = len(proofs[i].A.AuthPathsSuffixes[0])

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
			totalLeaves[i][j] = make([]frontend.Variable, len(proofs[i].B[j]))
			containerTotalLeaves[i][j] = make([]frontend.Variable, len(proofs[i].B[j]))
			totalLeafSiblingHashes[i][j] = make([]uints.U8, 32)
			containerTotalLeafSiblingHashes[i][j] = make([]uints.U8, 32)
		}

		containerTotalLeafIndexes[i] = make([]uints.U64, numOfLeavesProved)

		var authPathsTemp = make([][]KeccakDigest, numOfLeavesProved)
		var prevPath = proofs[i].A.AuthPathsSuffixes[0]
		authPathsTemp[0] = utilities.Reverse(prevPath)

		for j := range totalAuthPath[i][0] {
			totalAuthPath[i][0][j] = uints.NewU8Array(authPathsTemp[0][j].KeccakDigest[:])
		}

		for j := 1; j < numOfLeavesProved; j++ {
			prevPath = utilities.PrefixDecodePath(prevPath, proofs[i].A.AuthPathsPrefixLengths[j], proofs[i].A.AuthPathsSuffixes[j])
			authPathsTemp[j] = utilities.Reverse(prevPath)
			for z := 0; z < treeHeight; z++ {
				totalAuthPath[i][j][z] = uints.NewU8Array(authPathsTemp[j][z].KeccakDigest[:])
			}
		}
		totalLeafIndexes[i] = make([]uints.U64, numOfLeavesProved)

		for z := range numOfLeavesProved {
			totalLeafSiblingHashes[i][z] = uints.NewU8Array(proofs[i].A.LeafSiblingHashes[z].KeccakDigest[:])
			totalLeafIndexes[i][z] = uints.NewU64(proofs[i].A.LeafIndexes[z])
			// fmt.Println(proofs[i].B[z])
			for j := range proofs[i].B[z] {
				input := proofs[i].B[z][j]
				// fmt.Println("===============")
				// fmt.Println(j)
				// fmt.Println(input.Limbs)
				// fmt.Println("===============")
				totalLeaves[i][z][j] = typeConverters.LimbsToBigIntMod(input.Limbs)
			}
		}
	}
	startingDomainGen, _ := new(big.Int).SetString(cfg.DomainGenerator, 10)
	mvParamsNumberOfVariables := cfg.NVars
	foldingFactor := cfg.FoldingFactor
	var finalSumcheckRounds int

	if len(cfg.FoldingFactor) > 1 {
		foldingFactor = append(cfg.FoldingFactor, cfg.FoldingFactor[len(cfg.FoldingFactor)-1])
		finalSumcheckRounds = mvParamsNumberOfVariables % foldingFactor[len(foldingFactor)-1]
	} else {
		foldingFactor = []int{4}
		finalSumcheckRounds = mvParamsNumberOfVariables % 4
	}
	domainSize := (2 << mvParamsNumberOfVariables) * (1 << cfg.Rate) / 2
	oodSamples := cfg.OODSamples
	numOfQueries := cfg.NumQueries
	powBits := cfg.PowBits
	finalQueries := cfg.FinalQueries
	nRounds := cfg.NRounds
	statementPoints := make([][]frontend.Variable, 1)
	statementPoints[0] = make([]frontend.Variable, mvParamsNumberOfVariables)
	contStatementPoints := make([][]frontend.Variable, 1)
	contStatementPoints[0] = make([]frontend.Variable, mvParamsNumberOfVariables)
	for i := range mvParamsNumberOfVariables {
		statementPoints[0][i] = frontend.Variable(0)
		contStatementPoints[0][i] = frontend.Variable(0)
	}

	transcriptT := make([]uints.U8, cfg.TranscriptLen)
	contTranscript := make([]uints.U8, cfg.TranscriptLen)

	for i := range cfg.Transcript {
		transcriptT[i] = uints.NewU8(cfg.Transcript[i])
		contTranscript[i] = uints.NewU8(cfg.Transcript[i])
	}

	linearStatementValuesAtPoints := make([]frontend.Variable, len(proof_arg.StatementValuesAtRandomPoint))
	contLinearStatementValuesAtPoints := make([]frontend.Variable, len(proof_arg.StatementValuesAtRandomPoint))

	linearStatementEvaluations := make([]frontend.Variable, len(cfg.StatementEvaluations))
	contLinearStatementEvaluations := make([]frontend.Variable, len(cfg.StatementEvaluations))
	for i := range len(proof_arg.StatementValuesAtRandomPoint) {
		linearStatementValuesAtPoints[i] = typeConverters.LimbsToBigIntMod(proof_arg.StatementValuesAtRandomPoint[i].Limbs)
		contLinearStatementValuesAtPoints[i] = typeConverters.LimbsToBigIntMod(proof_arg.StatementValuesAtRandomPoint[i].Limbs)
		x, _ := new(big.Int).SetString(cfg.StatementEvaluations[i], 10)
		linearStatementEvaluations[i] = frontend.Variable(x)
		contLinearStatementEvaluations[i] = frontend.Variable(x)
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

	var circuit = Circuit{
		IO:                                   []byte(cfg.IOPattern),
		Transcript:                           contTranscript,
		RoundParametersOODSamples:            oodSamples,
		RoundParametersNumOfQueries:          numOfQueries,
		StartingDomainBackingDomainGenerator: startingDomainGen,
		ParamNRounds:                         nRounds,
		FoldOptimisation:                     true,
		InitialStatement:                     true,
		CommittmentOODSamples:                1,
		DomainSize:                           domainSize,
		FoldingFactorArray:                   foldingFactor,
		MVParamsNumberOfVariables:            mvParamsNumberOfVariables,
		FinalSumcheckRounds:                  finalSumcheckRounds,
		PowBits:                              powBits,
		FinalPowBits:                         cfg.FinalPowBits,
		FinalFoldingPowBits:                  cfg.FinalFoldingPowBits,
		FinalQueries:                         finalQueries,
		StatementPoints:                      contStatementPoints,
		StatementEvaluations:                 0,
		LinearStatementEvaluations:           contLinearStatementEvaluations,
		LinearStatementValuesAtPoints:        contLinearStatementValuesAtPoints,
		Leaves:                               containerTotalLeaves,
		LeafIndexes:                          containerTotalLeafIndexes,
		LeafSiblingHashes:                    containerTotalLeafSiblingHashes,
		AuthPaths:                            containerTotalAuthPath,
		NVars:                                cfg.NVars,
		LogNumConstraints:                    cfg.LogNumConstraints,
		MatrixA:                              matrixA,
		MatrixB:                              matrixB,
		MatrixC:                              matrixC,
	}

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(ccs)

	assignment := Circuit{
		IO:                                   []byte(cfg.IOPattern),
		Transcript:                           transcriptT,
		FoldOptimisation:                     true,
		InitialStatement:                     true,
		CommittmentOODSamples:                1,
		DomainSize:                           domainSize,
		StartingDomainBackingDomainGenerator: startingDomainGen,
		FoldingFactorArray:                   foldingFactor,
		PowBits:                              powBits,
		FinalPowBits:                         cfg.FinalPowBits,
		FinalFoldingPowBits:                  cfg.FinalFoldingPowBits,
		FinalSumcheckRounds:                  finalSumcheckRounds,
		MVParamsNumberOfVariables:            mvParamsNumberOfVariables,
		RoundParametersOODSamples:            oodSamples,
		RoundParametersNumOfQueries:          numOfQueries,
		ParamNRounds:                         nRounds,
		FinalQueries:                         finalQueries,
		StatementPoints:                      statementPoints,
		StatementEvaluations:                 0,
		LinearStatementEvaluations:           linearStatementEvaluations,
		LinearStatementValuesAtPoints:        linearStatementValuesAtPoints,
		Leaves:                               totalLeaves,
		LeafIndexes:                          totalLeafIndexes,
		LeafSiblingHashes:                    totalLeafSiblingHashes,
		AuthPaths:                            totalAuthPath,
		NVars:                                cfg.NVars,
		LogNumConstraints:                    cfg.LogNumConstraints,
		MatrixA:                              matrixA,
		MatrixB:                              matrixB,
		MatrixC:                              matrixC,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, pk, witness, backend.WithSolverOptions(solver.WithHints(utilities.IndexOf)))
	groth16.Verify(proof, vk, publicWitness)
}
