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
	api.Println(t_rand)
	// api.Println(sp_rand)
	api.Println(savedValForSumcheck)

	rootHashes, batchingRandomness, initialOODQueries, initialOODAnswers, err := parseBatchedCommitment(api, arthur, circuit)
	if err != nil {
		return err
	}

	initialOODs := oodAnswers(api, initialOODAnswers, batchingRandomness)

	batchSizeLen := circuit.BatchSize

	initialSumcheckData, lastEval, initialSumcheckFoldingRandomness, err := initialSumcheck(api, circuit, arthur, initialOODQueries, initialOODs)

	api.Println(lastEval)
	if err != nil {
		return err
	}
	copyOfFirstLeaves := make([][][]frontend.Variable, len(circuit.FirstRoundPaths.Leaves))
	for i := range len(circuit.FirstRoundPaths.Leaves) {
		copyOfFirstLeaves[i] = make([][]frontend.Variable, len(circuit.FirstRoundPaths.Leaves[i]))
		for j := range len(circuit.FirstRoundPaths.Leaves[i]) {
			copyOfFirstLeaves[i][j] = make([]frontend.Variable, len(circuit.FirstRoundPaths.Leaves[i][j]))
			for k := range len(circuit.FirstRoundPaths.Leaves[i][j]) {
				copyOfFirstLeaves[i][j][k] = circuit.FirstRoundPaths.Leaves[i][j][k]
			}
		}
	}

	computedFolded := combineFirstRoundLeaves(api, copyOfFirstLeaves, batchingRandomness)
	roundAnswers := make([][][]frontend.Variable, len(circuit.MerklePaths.Leaves)+1)
	roundAnswers[0] = computedFolded
	for i := range len(circuit.MerklePaths.Leaves) {
		roundAnswers[i+1] = circuit.MerklePaths.Leaves[i]
	}

	computedFold := computeFold(computedFolded, initialSumcheckFoldingRandomness, api)
	api.Println(computedFold)
	mainRoundData := generateEmptyMainRoundData(circuit)
	expDomainGenerator := utilities.Exponent(api, uapi, circuit.StartingDomainBackingDomainGenerator, uints.NewU64(uint64(1<<circuit.FoldingFactorArray[0])))
	domainSize := circuit.DomainSize

	totalFoldingRandomness := initialSumcheckFoldingRandomness

	rootHashList := make([]frontend.Variable, len(circuit.RoundParametersOODSamples))

	for r := range circuit.RoundParametersOODSamples {
		rootHash := make([]frontend.Variable, 1)
		if err := arthur.FillNextScalars(rootHash); err != nil {
			return err
		}
		rootHashList[r] = rootHash[0]
		a, roundOODAnswers, err := FillInOODPointsAndAnswers(circuit.RoundParametersOODSamples[r], arthur)
		if err != nil {
			return err
		}

		mainRoundData.OODPoints[r] = a

		stirChallengeIndexes, err := GetStirChallenges(api, *circuit, arthur, circuit.RoundParametersNumOfQueries[r], domainSize, r)
		if err != nil {
			return err
		}

		if r == 0 {
			err = ValidateFirstRound(api, circuit, arthur, uapi, sc, batchSizeLen, rootHashes, batchingRandomness, stirChallengeIndexes, roundAnswers[0])
			if err != nil {
				return err
			}

			mainRoundData.StirChallengesPoints[r] = make([]frontend.Variable, len(circuit.FirstRoundPaths.LeafIndexes[r]))
			for index := range circuit.FirstRoundPaths.LeafIndexes[r] {
				mainRoundData.StirChallengesPoints[r][index] = utilities.Exponent(api, uapi, expDomainGenerator, circuit.FirstRoundPaths.LeafIndexes[r][index])
			}
		} else {
			err := VerifyMerkleTreeProofs(api, uapi, sc, circuit.MerklePaths.LeafIndexes[r-1], roundAnswers[r], circuit.MerklePaths.LeafSiblingHashes[r-1], circuit.MerklePaths.AuthPaths[r-1], rootHashList[r-1])
			if err != nil {
				return err
			}
			err = utilities.IsSubset(api, uapi, arthur, stirChallengeIndexes, circuit.MerklePaths.LeafIndexes[r-1])
			if err != nil {
				return err
			}
			mainRoundData.StirChallengesPoints[r] = make([]frontend.Variable, len(circuit.MerklePaths.LeafIndexes[r-1]))
			for index := range circuit.MerklePaths.LeafIndexes[r-1] {
				mainRoundData.StirChallengesPoints[r][index] = utilities.Exponent(api, uapi, expDomainGenerator, circuit.MerklePaths.LeafIndexes[r-1][index])
			}
		}

		if err = RunPoW(api, sc, arthur, circuit.PowBits[r]); err != nil {
			return err
		}

		mainRoundData.CombinationRandomness[r], err = GenerateCombinationRandomness(api, arthur, len(roundOODAnswers)+len(computedFold))
		if err != nil {
			return err
		}

		lastEval = api.Add(lastEval, calculateShiftValue(roundOODAnswers, mainRoundData.CombinationRandomness[r], computedFold, api))

		var roundFoldingRandomness []frontend.Variable
		roundFoldingRandomness, lastEval, err = runSumcheckRounds(api, lastEval, arthur, circuit.FoldingFactorArray[r], 3)
		if err != nil {
			return nil
		}

		computedFold = computeFold(circuit.MerklePaths.Leaves[r], roundFoldingRandomness, api)
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

	evaluationOfWPoly := ComputeWPoly(
		api,
		circuit,
		initialOODQueries,
		initialSumcheckData,
		mainRoundData,
		sp_rand,
		totalFoldingRandomness,
	)

	api.AssertIsEqual(
		lastEval,
		api.Mul(evaluationOfWPoly, utilities.MultivarPoly(finalCoefficients, finalSumcheckRandomness, api)),
	)

	// x := api.Mul(api.Sub(api.Mul(circuit.LinearStatementEvaluations[0], circuit.LinearStatementEvaluations[1]), circuit.LinearStatementEvaluations[2]), calculateEQ(api, sp_rand, t_rand))
	// api.AssertIsEqual(savedValForSumcheck, x)
	return nil
}

func oodAnswers(
	api frontend.API,
	answers [][]frontend.Variable,
	randomness frontend.Variable,
) (result []frontend.Variable) {

	if len(answers) == 0 {
		return nil
	}

	multiplier := frontend.Variable(1)

	first := answers[0]
	result = make([]frontend.Variable, len(first))
	for j := range first {
		result[j] = api.Mul(first[j], multiplier)
	}

	for i := 1; i < len(answers); i++ {
		multiplier = api.Mul(multiplier, randomness)

		round := answers[i]
		for j := range round {
			term := api.Mul(round[j], multiplier)
			result[j] = api.Add(result[j], term)
		}
	}

	return result
}

type MerkleObject struct {
	AuthPaths                  [][][][]uints.U8
	Leaves                     [][][]frontend.Variable
	LeafSiblingHashes          [][][]uints.U8
	LeafIndexes                [][]uints.U64
	ContainerAuthPaths         [][][][]uints.U8
	ContainerLeaves            [][][]frontend.Variable
	ContainerLeafSiblingHashes [][][]uints.U8
	ContainerLeafIndexes       [][]uints.U64
}

func ParsePathsObject(proofElements []ProofElement) MerkleObject {
	var totalAuthPath = make([][][][]uints.U8, len(proofElements))
	var totalLeaves = make([][][]frontend.Variable, len(proofElements))
	var totalLeafSiblingHashes = make([][][]uints.U8, len(proofElements))
	var totalLeafIndexes = make([][]uints.U64, len(proofElements))

	var containerTotalAuthPath = make([][][][]uints.U8, len(proofElements))
	var containerTotalLeaves = make([][][]frontend.Variable, len(proofElements))
	var containerTotalLeafSiblingHashes = make([][][]uints.U8, len(proofElements))
	var containerTotalLeafIndexes = make([][]uints.U64, len(proofElements))

	for i := range proofElements {
		var numOfLeavesProved = len(proofElements[i].A.LeafIndexes)
		var treeHeight = len(proofElements[i].A.AuthPathsSuffixes[0])

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
			totalLeaves[i][j] = make([]frontend.Variable, len(proofElements[i].B[j]))
			containerTotalLeaves[i][j] = make([]frontend.Variable, len(proofElements[i].B[j]))
			totalLeafSiblingHashes[i][j] = make([]uints.U8, 32)
			containerTotalLeafSiblingHashes[i][j] = make([]uints.U8, 32)
		}

		containerTotalLeafIndexes[i] = make([]uints.U64, numOfLeavesProved)

		var authPathsTemp = make([][]KeccakDigest, numOfLeavesProved)
		var prevPath = proofElements[i].A.AuthPathsSuffixes[0]
		authPathsTemp[0] = utilities.Reverse(prevPath)

		for j := range totalAuthPath[i][0] {
			totalAuthPath[i][0][j] = uints.NewU8Array(authPathsTemp[0][j].KeccakDigest[:])
		}

		for j := 1; j < numOfLeavesProved; j++ {
			prevPath = utilities.PrefixDecodePath(prevPath, proofElements[i].A.AuthPathsPrefixLengths[j], proofElements[i].A.AuthPathsSuffixes[j])
			authPathsTemp[j] = utilities.Reverse(prevPath)
			for z := 0; z < treeHeight; z++ {
				totalAuthPath[i][j][z] = uints.NewU8Array(authPathsTemp[j][z].KeccakDigest[:])
			}
		}
		totalLeafIndexes[i] = make([]uints.U64, numOfLeavesProved)

		for z := range numOfLeavesProved {
			totalLeafSiblingHashes[i][z] = uints.NewU8Array(proofElements[i].A.LeafSiblingHashes[z].KeccakDigest[:])
			totalLeafIndexes[i][z] = uints.NewU64(proofElements[i].A.LeafIndexes[z])
			for j := range proofElements[i].B[z] {
				input := proofElements[i].B[z][j]
				totalLeaves[i][z][j] = typeConverters.LimbsToBigIntMod(input.Limbs)
			}
		}
	}

	return MerkleObject{
		AuthPaths:                  totalAuthPath,
		Leaves:                     totalLeaves,
		LeafSiblingHashes:          totalLeafSiblingHashes,
		LeafIndexes:                totalLeafIndexes,
		ContainerAuthPaths:         containerTotalAuthPath,
		ContainerLeaves:            containerTotalLeaves,
		ContainerLeafSiblingHashes: containerTotalLeafSiblingHashes,
		ContainerLeafIndexes:       containerTotalLeafIndexes,
	}
}

func verify_circuit(
	proof_arg ProofObject, cfg Config, internedR1CS R1CS, interner Interner, pk *groth16.ProvingKey,
	vk *groth16.VerifyingKey, outputCcsPath string,
) {
	merkleObject := ParsePathsObject(proof_arg.MerklePaths)
	firstRoundMerkleObject := ParsePathsObject(proof_arg.FirstRoundPaths)

	startingDomainGen, _ := new(big.Int).SetString(cfg.DomainGenerator, 10)
	mvParamsNumberOfVariables := cfg.NVars
	var foldingFactor []int
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

	var merklePaths = MerklePaths{
		Leaves:            merkleObject.ContainerLeaves,
		LeafIndexes:       merkleObject.ContainerLeafIndexes,
		LeafSiblingHashes: merkleObject.ContainerLeafSiblingHashes,
		AuthPaths:         merkleObject.ContainerAuthPaths,
	}
	var firstRoundPathsForCircuit = MerklePaths{
		Leaves:            firstRoundMerkleObject.ContainerLeaves,
		LeafIndexes:       firstRoundMerkleObject.ContainerLeafIndexes,
		LeafSiblingHashes: firstRoundMerkleObject.ContainerLeafSiblingHashes,
		AuthPaths:         firstRoundMerkleObject.ContainerAuthPaths,
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
		BatchSize:                            len(proof_arg.FirstRoundPaths),
		LinearStatementEvaluations:           contLinearStatementEvaluations,
		LinearStatementValuesAtPoints:        contLinearStatementValuesAtPoints,
		MerklePaths:                          merklePaths,
		FirstRoundPaths:                      firstRoundPathsForCircuit,
		NVars:                                cfg.NVars,
		LogNumConstraints:                    cfg.LogNumConstraints,
		MatrixA:                              matrixA,
		MatrixB:                              matrixB,
		MatrixC:                              matrixC,
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

	merklePaths = MerklePaths{
		Leaves:            merkleObject.Leaves,
		LeafIndexes:       merkleObject.LeafIndexes,
		LeafSiblingHashes: merkleObject.LeafSiblingHashes,
		AuthPaths:         merkleObject.AuthPaths,
	}
	firstRoundPathsForCircuit = MerklePaths{
		Leaves:            firstRoundMerkleObject.Leaves,
		LeafIndexes:       firstRoundMerkleObject.LeafIndexes,
		LeafSiblingHashes: firstRoundMerkleObject.LeafSiblingHashes,
		AuthPaths:         firstRoundMerkleObject.AuthPaths,
	}

	assignment := Circuit{
		IO:                                   []byte(cfg.IOPattern),
		Transcript:                           transcriptT,
		FoldOptimisation:                     true,
		InitialStatement:                     true,
		DomainSize:                           domainSize,
		BatchSize:                            len(proof_arg.FirstRoundPaths),
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
		MerklePaths:                          merklePaths,
		FirstRoundPaths:                      firstRoundPathsForCircuit,
		NVars:                                cfg.NVars,
		LogNumConstraints:                    cfg.LogNumConstraints,
		MatrixA:                              matrixA,
		MatrixB:                              matrixB,
		MatrixC:                              matrixC,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, *pk, witness, backend.WithSolverOptions(solver.WithHints(utilities.IndexOf)))
	err = groth16.Verify(proof, *vk, publicWitness)
	if err != nil {
		fmt.Println(err)
	}
}
