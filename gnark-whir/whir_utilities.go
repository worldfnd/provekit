package main

import (
	"math/big"
	"math/bits"
	"reilabs/whir-verifier-circuit/typeConverters"
	"reilabs/whir-verifier-circuit/utilities"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnark_nimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

type WHIRParams struct {
	ParamNRounds                         int
	FoldingFactorArray                   []int
	RoundParametersOODSamples            []int
	RoundParametersNumOfQueries          []int
	PowBits                              []int
	FinalQueries                         int
	FinalPowBits                         int
	FinalFoldingPowBits                  int
	StartingDomainBackingDomainGenerator frontend.Variable
	DomainSize                           int
	CommittmentOODSamples                int
	FinalSumcheckRounds                  int
	MVParamsNumberOfVariables            int
}

func runWhir(
	api frontend.API,
	arthur gnark_nimue.Arthur,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
	circuit Merkle,
	whirParams WHIRParams,
	linearStatementEvaluations []frontend.Variable,
	linearStatementValuesAtPoints []frontend.Variable,
) (totalFoldingRandomness []frontend.Variable, err error) {
	if err = FillInAndVerifyRootHash(0, api, uapi, sc, circuit, arthur); err != nil {
		return
	}

	initialOODQueries, initialOODAnswers, tempErr := FillInOODPointsAndAnswers(whirParams.CommittmentOODSamples, arthur)
	if tempErr != nil {
		err = tempErr
		return
	}

	initialCombinationRandomness, tempErr := GenerateCombinationRandomness(api, arthur, whirParams.CommittmentOODSamples+len(linearStatementEvaluations))
	if tempErr != nil {
		err = tempErr
		return
	}

	OODAnswersAndStatmentEvaluations := append(initialOODAnswers, linearStatementEvaluations...)
	lastEval := utilities.DotProduct(api, initialCombinationRandomness, OODAnswersAndStatmentEvaluations)

	initialSumcheckFoldingRandomness, lastEval, tempErr := runWhirSumcheckRounds(api, lastEval, arthur, whirParams.FoldingFactorArray[0], 3)
	if tempErr != nil {
		err = tempErr
		return
	}

	initialData := InitialSumcheckData{
		InitialOODQueries:            initialOODQueries,
		InitialCombinationRandomness: initialCombinationRandomness,
	}

	computedFold := computeFold(circuit.Leaves[0], initialSumcheckFoldingRandomness, api)

	mainRoundData := generateEmptyMainRoundData(whirParams)

	expDomainGenerator := utilities.Exponent(api, uapi, whirParams.StartingDomainBackingDomainGenerator, uints.NewU64(uint64(1<<whirParams.FoldingFactorArray[0])))
	domainSize := whirParams.DomainSize

	totalFoldingRandomness = initialSumcheckFoldingRandomness

	for r := range whirParams.ParamNRounds {
		if err = FillInAndVerifyRootHash(r+1, api, uapi, sc, circuit, arthur); err != nil {
			return
		}

		var roundOODAnswers []frontend.Variable
		mainRoundData.OODPoints[r], roundOODAnswers, err = FillInOODPointsAndAnswers(whirParams.RoundParametersOODSamples[r], arthur)
		if err != nil {
			return
		}

		if err = RunPoW(api, sc, arthur, whirParams.PowBits[r]); err != nil {
			return
		}

		mainRoundData.StirChallengesPoints[r], err = GenerateStirChallengePoints(api, arthur, whirParams.RoundParametersNumOfQueries[r], circuit.LeafIndexes[r], domainSize, uapi, expDomainGenerator, whirParams.FoldingFactorArray[r])
		if err != nil {
			return
		}

		mainRoundData.CombinationRandomness[r], err = GenerateCombinationRandomness(api, arthur, len(circuit.LeafIndexes[r])+whirParams.RoundParametersOODSamples[r])
		if err != nil {
			return
		}

		lastEval = api.Add(lastEval, calculateShiftValue(roundOODAnswers, mainRoundData.CombinationRandomness[r], computedFold, api))

		var roundFoldingRandomness []frontend.Variable
		roundFoldingRandomness, lastEval, err = runWhirSumcheckRounds(api, lastEval, arthur, whirParams.FoldingFactorArray[r], 3)
		if err != nil {
			return
		}

		computedFold = computeFold(circuit.Leaves[r+1], roundFoldingRandomness, api)
		totalFoldingRandomness = append(totalFoldingRandomness, roundFoldingRandomness...)

		domainSize /= 2
		expDomainGenerator = api.Mul(expDomainGenerator, expDomainGenerator)
	}

	finalCoefficients := make([]frontend.Variable, 1<<whirParams.FinalSumcheckRounds)
	if err = arthur.FillNextScalars(finalCoefficients); err != nil {
		return
	}

	if err = RunPoW(api, sc, arthur, whirParams.FinalPowBits); err != nil {
		return
	}

	finalRandomnessPoints, err := GenerateStirChallengePoints(api, arthur, whirParams.FinalQueries, circuit.LeafIndexes[whirParams.ParamNRounds], domainSize, uapi, expDomainGenerator, whirParams.FoldingFactorArray[whirParams.ParamNRounds])
	if err != nil {
		return
	}

	finalEvaluations := utilities.UnivarPoly(api, finalCoefficients, finalRandomnessPoints)

	for foldIndex := range computedFold {
		api.AssertIsEqual(computedFold[foldIndex], finalEvaluations[foldIndex])
	}

	finalSumcheckRandomness, lastEval, tempErr := runWhirSumcheckRounds(api, lastEval, arthur, whirParams.FinalSumcheckRounds, 3)
	if tempErr != nil {
		err = tempErr
		return
	}

	totalFoldingRandomness = append(totalFoldingRandomness, finalSumcheckRandomness...)

	totalFoldingRandomness = utilities.Reverse(totalFoldingRandomness)

	evaluationOfVPoly := ComputeWPoly(
		api,
		whirParams,
		initialData,
		mainRoundData,
		totalFoldingRandomness,
		linearStatementValuesAtPoints,
	)

	api.AssertIsEqual(
		lastEval,
		api.Mul(evaluationOfVPoly, utilities.MultivarPoly(finalCoefficients, finalSumcheckRandomness, api)),
	)

	err = nil
	return
}

func VerifyMerkleTreeProofs(api frontend.API, uapi *uints.BinaryField[uints.U64], sc *skyscraper.Skyscraper, leafIndexes []uints.U64, leaves [][]frontend.Variable, leafSiblingHashes [][]uints.U8, authPaths [][][]uints.U8, rootHash frontend.Variable) error {
	numOfLeavesProved := len(leaves)
	for i := range numOfLeavesProved {
		treeHeight := len(authPaths[i]) + 1
		leafIndexBits := api.ToBinary(uapi.ToValue(leafIndexes[i]), treeHeight)
		leafSiblingHash := typeConverters.LittleEndianFromUints(api, leafSiblingHashes[i])

		claimedLeafHash := sc.Compress(leaves[i][0], leaves[i][1])
		for x := range len(leaves[i]) - 2 {
			claimedLeafHash = sc.Compress(claimedLeafHash, leaves[i][x+2])
		}

		dir := leafIndexBits[0]

		xLeftChild := api.Select(dir, leafSiblingHash, claimedLeafHash)
		xRightChild := api.Select(dir, claimedLeafHash, leafSiblingHash)

		currentHash := sc.Compress(xLeftChild, xRightChild)

		for level := 1; level < treeHeight; level++ {
			indexBit := leafIndexBits[level]

			siblingHash := typeConverters.LittleEndianFromUints(api, authPaths[i][level-1])

			dir := api.And(indexBit, 1)
			left := api.Select(dir, siblingHash, currentHash)
			right := api.Select(dir, currentHash, siblingHash)

			currentHash = sc.Compress(left, right)
		}
		api.AssertIsEqual(currentHash, rootHash)
	}
	return nil
}

func GetStirChallenges(
	api frontend.API,
	arthur gnark_nimue.Arthur,
	numQueries int,
	domainSize int,
	foldingFactorPower int,
) ([]frontend.Variable, error) {
	foldedDomainSize := domainSize / foldingFactorPower
	domainSizeBytes := (bits.Len(uint(foldedDomainSize*2-1)) - 1 + 7) / 8

	stirQueries := make([]uints.U8, domainSizeBytes*numQueries)
	if err := arthur.FillChallengeBytes(stirQueries); err != nil {
		return nil, err
	}

	bitLength := bits.Len(uint(foldedDomainSize)) - 1

	indexes := make([]frontend.Variable, numQueries)
	for i := range numQueries {
		var value frontend.Variable = 0
		for j := range domainSizeBytes {
			value = api.Add(stirQueries[j+i*domainSizeBytes].Val, api.Mul(value, 256))
		}

		bitsOfValue := api.ToBinary(value)
		indexes[i] = api.FromBinary(bitsOfValue[:bitLength]...)
	}

	return indexes, nil
}

type MainRoundData struct {
	OODPoints             [][]frontend.Variable
	StirChallengesPoints  [][]frontend.Variable
	CombinationRandomness [][]frontend.Variable
}

func generateEmptyMainRoundData(circuit WHIRParams) MainRoundData {
	return MainRoundData{
		OODPoints:             make([][]frontend.Variable, len(circuit.RoundParametersOODSamples)),
		StirChallengesPoints:  make([][]frontend.Variable, len(circuit.RoundParametersOODSamples)),
		CombinationRandomness: make([][]frontend.Variable, len(circuit.RoundParametersOODSamples)),
	}
}

type InitialSumcheckData struct {
	InitialOODQueries            []frontend.Variable
	InitialCombinationRandomness []frontend.Variable
}

func FillInOODPointsAndAnswers(numberOfOODPoints int, arthur gnark_nimue.Arthur) ([]frontend.Variable, []frontend.Variable, error) {
	oodPoints := make([]frontend.Variable, numberOfOODPoints)
	oodAnswers := make([]frontend.Variable, numberOfOODPoints)

	if err := arthur.FillChallengeScalars(oodPoints); err != nil {
		return nil, nil, err
	}

	if err := arthur.FillNextScalars(oodAnswers); err != nil {
		return nil, nil, err
	}

	return oodPoints, oodAnswers, nil
}

func RunPoW(api frontend.API, sc *skyscraper.Skyscraper, arthur gnark_nimue.Arthur, difficulty int) error {
	if difficulty > 0 {
		_, _, err := utilities.PoW(api, sc, arthur, difficulty)
		if err != nil {
			return err
		}
	}
	return nil
}

func GenerateStirChallengePoints(
	api frontend.API,
	arthur gnark_nimue.Arthur,
	NQueries int,
	leafIndexes []uints.U64,
	domainSize int,
	uapi *uints.BinaryField[uints.U64],
	expDomainGenerator frontend.Variable,
	foldingFactor int,
) ([]frontend.Variable, error) {
	foldingFactorPower := 1 << foldingFactor
	finalIndexes, err := GetStirChallenges(api, arthur, NQueries, domainSize, foldingFactorPower)
	if err != nil {
		api.Println(err)
		return nil, err
	}

	err = utilities.IsSubset(api, uapi, arthur, finalIndexes, leafIndexes)
	if err != nil {
		return nil, err
	}

	finalRandomnessPoints := make([]frontend.Variable, len(leafIndexes))

	for index := range leafIndexes {
		finalRandomnessPoints[index] = utilities.Exponent(api, uapi, expDomainGenerator, leafIndexes[index])
	}

	return finalRandomnessPoints, nil
}

func GenerateCombinationRandomness(api frontend.API, arthur gnark_nimue.Arthur, randomnessLength int) ([]frontend.Variable, error) {
	combRandomnessGen := make([]frontend.Variable, 1)
	if err := arthur.FillChallengeScalars(combRandomnessGen); err != nil {
		return nil, err
	}

	combinationRandomness := utilities.ExpandRandomness(api, combRandomnessGen[0], randomnessLength)
	return combinationRandomness, nil

}

func runWhirSumcheckRounds(
	api frontend.API,
	lastEval frontend.Variable,
	arthur gnark_nimue.Arthur,
	foldingFactor int,
	polynomialDegree int,
) ([]frontend.Variable, frontend.Variable, error) {
	sumcheckPolynomial := make([]frontend.Variable, polynomialDegree)
	foldingRandomness := make([]frontend.Variable, foldingFactor)
	foldingRandomnessTemp := make([]frontend.Variable, 1)

	for i := range foldingFactor {
		if err := arthur.FillNextScalars(sumcheckPolynomial); err != nil {
			return nil, nil, err
		}
		if err := arthur.FillChallengeScalars(foldingRandomnessTemp); err != nil {
			return nil, nil, err
		}
		foldingRandomness[i] = foldingRandomnessTemp[0]
		utilities.CheckSumOverBool(api, lastEval, sumcheckPolynomial)
		lastEval = utilities.EvaluateQuadraticPolynomialFromEvaluationList(api, sumcheckPolynomial, foldingRandomness[i])
	}
	return foldingRandomness, lastEval, nil
}

func ComputeWPoly(
	api frontend.API,
	circuit WHIRParams,
	initialData InitialSumcheckData,
	mainRoundData MainRoundData,
	totalFoldingRandomness []frontend.Variable,
	linearStatementValuesAtPoints []frontend.Variable,
) frontend.Variable {
	numberVars := circuit.MVParamsNumberOfVariables

	value := frontend.Variable(0)
	for j := range initialData.InitialOODQueries {
		value = api.Add(value, api.Mul(initialData.InitialCombinationRandomness[j], utilities.EqPolyOutside(api, utilities.ExpandFromUnivariate(api, initialData.InitialOODQueries[j], numberVars), totalFoldingRandomness)))
	}

	for j, linearStatementValueAtPoint := range linearStatementValuesAtPoints {
		value = api.Add(value, api.Mul(initialData.InitialCombinationRandomness[len(initialData.InitialOODQueries)+j], linearStatementValueAtPoint))
	}

	for r := range mainRoundData.OODPoints {
		numberVars -= circuit.FoldingFactorArray[r]
		newTmpArr := append(mainRoundData.OODPoints[r], mainRoundData.StirChallengesPoints[r]...)

		sumOfClaims := frontend.Variable(0)
		for i := range newTmpArr {
			point := utilities.ExpandFromUnivariate(api, newTmpArr[i], numberVars)
			sumOfClaims = api.Add(sumOfClaims, api.Mul(utilities.EqPolyOutside(api, point, totalFoldingRandomness[0:numberVars]), mainRoundData.CombinationRandomness[r][i]))
		}
		value = api.Add(value, sumOfClaims)
	}

	return value
}

func FillInAndVerifyRootHash(
	roundNum int,
	api frontend.API,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
	circuit Merkle,
	arthur gnark_nimue.Arthur,
) error {
	rootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(rootHash); err != nil {
		return err
	}
	err := VerifyMerkleTreeProofs(api, uapi, sc, circuit.LeafIndexes[roundNum], circuit.Leaves[roundNum], circuit.LeafSiblingHashes[roundNum], circuit.AuthPaths[roundNum], rootHash[0])
	if err != nil {
		return err
	}
	return nil
}

func computeFold(leaves [][]frontend.Variable, foldingRandomness []frontend.Variable, api frontend.API) []frontend.Variable {
	computedFold := make([]frontend.Variable, len(leaves))
	for j := range leaves {
		computedFold[j] = utilities.MultivarPoly(leaves[j], foldingRandomness, api)
	}
	return computedFold
}

func calculateShiftValue(oodAnswers []frontend.Variable, combinationRandomness []frontend.Variable, computedFold []frontend.Variable, api frontend.API) frontend.Variable {
	return utilities.DotProduct(api, append(oodAnswers, computedFold...), combinationRandomness)
}

func newMerkle(
	hint Hint,
	isContainer bool,
) Merkle {
	var totalAuthPath = make([][][][]uints.U8, len(hint.merklePaths))
	var totalLeaves = make([][][]frontend.Variable, len(hint.merklePaths))
	var totalLeafSiblingHashes = make([][][]uints.U8, len(hint.merklePaths))
	var totalLeafIndexes = make([][]uints.U64, len(hint.merklePaths))

	for i, merkle_path := range hint.merklePaths {
		var numOfLeavesProved = len(merkle_path.LeafIndexes)
		var treeHeight = len(merkle_path.AuthPathsSuffixes[0])

		totalAuthPath[i] = make([][][]uints.U8, numOfLeavesProved)
		totalLeaves[i] = make([][]frontend.Variable, numOfLeavesProved)
		totalLeafSiblingHashes[i] = make([][]uints.U8, numOfLeavesProved)

		for j := range numOfLeavesProved {
			totalAuthPath[i][j] = make([][]uints.U8, treeHeight)

			for z := range treeHeight {
				totalAuthPath[i][j][z] = make([]uints.U8, 32)
			}
			totalLeaves[i][j] = make([]frontend.Variable, len(hint.stirAnswers[i][j]))
			totalLeafSiblingHashes[i][j] = make([]uints.U8, 32)
		}

		totalLeafIndexes[i] = make([]uints.U64, numOfLeavesProved)

		if !isContainer {
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

			for z := range numOfLeavesProved {
				totalLeafSiblingHashes[i][z] = uints.NewU8Array(merkle_path.LeafSiblingHashes[z].KeccakDigest[:])
				totalLeafIndexes[i][z] = uints.NewU64(merkle_path.LeafIndexes[z])
				for j := range hint.stirAnswers[i][z] {
					input := hint.stirAnswers[i][z][j]
					totalLeaves[i][z][j] = typeConverters.LimbsToBigIntMod(input.Limbs)
				}
			}
		}
	}

	return Merkle{
		Leaves:            totalLeaves,
		LeafIndexes:       totalLeafIndexes,
		LeafSiblingHashes: totalLeafSiblingHashes,
		AuthPaths:         totalAuthPath,
	}
}

type Merkle struct {
	Leaves            [][][]frontend.Variable
	LeafIndexes       [][]uints.U64
	LeafSiblingHashes [][][]uints.U8
	AuthPaths         [][][][]uints.U8
}

func new_whir_params(cfg WHIRConfig) WHIRParams {
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

	return WHIRParams{
		ParamNRounds:                         cfg.NRounds,
		FoldingFactorArray:                   foldingFactor,
		RoundParametersOODSamples:            cfg.OODSamples,
		RoundParametersNumOfQueries:          cfg.NumQueries,
		PowBits:                              cfg.PowBits,
		FinalQueries:                         cfg.FinalQueries,
		FinalPowBits:                         cfg.FinalPowBits,
		FinalFoldingPowBits:                  cfg.FinalFoldingPowBits,
		StartingDomainBackingDomainGenerator: *startingDomainGen,
		DomainSize:                           domainSize,
		CommittmentOODSamples:                1,
		FinalSumcheckRounds:                  finalSumcheckRounds,
		MVParamsNumberOfVariables:            mvParamsNumberOfVariables,
	}
}
