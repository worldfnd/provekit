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

func calculateEQ(api frontend.API, alphas []frontend.Variable, r []frontend.Variable) frontend.Variable {
	ans := frontend.Variable(1)
	for i, alpha := range alphas {
		ans = api.Mul(ans, api.Add(api.Mul(alpha, r[i]), api.Mul(api.Sub(frontend.Variable(1), alpha), api.Sub(frontend.Variable(1), r[i]))))
	}
	return ans
}

func GetStirChallenges(
	api frontend.API,
	circuit Circuit,
	arthur gnark_nimue.Arthur,
	numQueries int,
	domainSize int,
	roundIndex int,
) ([]frontend.Variable, error) {
	foldedDomainSize := domainSize / (1 << circuit.FoldingFactorArray[roundIndex])
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

type Circuit struct {
	// Inputs
	DomainSize                           int
	StartingDomainBackingDomainGenerator frontend.Variable
	CommittmentOODSamples                int
	FoldingFactorArray                   []int
	FinalSumcheckRounds                  int
	ParamNRounds                         int
	MVParamsNumberOfVariables            int
	RoundParametersOODSamples            []int
	RoundParametersNumOfQueries          []int
	InitialStatement                     bool
	FoldOptimisation                     bool
	PowBits                              []int
	FinalPowBits                         int
	FinalFoldingPowBits                  int
	FinalQueries                         int
	Leaves                               [][][]frontend.Variable
	LeafIndexes                          [][]uints.U64
	LeafSiblingHashes                    [][][]uints.U8
	AuthPaths                            [][][][]uints.U8
	StatementPoints                      [][]frontend.Variable
	StatementEvaluations                 int
	LinearStatementValuesAtPoints        []frontend.Variable
	LinearStatementEvaluations           []frontend.Variable
	NVars                                int
	LogNumConstraints                    int
	MatrixA                              []MatrixCell
	MatrixB                              []MatrixCell
	MatrixC                              []MatrixCell
	// Public Input
	IO         []byte
	Transcript []uints.U8 `gnark:",public"`
}

type MainRoundData struct {
	OODPoints             [][]frontend.Variable
	StirChallengesPoints  [][]frontend.Variable
	CombinationRandomness [][]frontend.Variable
}

func generateEmptyMainRoundData(circuit *Circuit) MainRoundData {
	return MainRoundData{
		OODPoints:             make([][]frontend.Variable, len(circuit.RoundParametersOODSamples)),
		StirChallengesPoints:  make([][]frontend.Variable, len(circuit.RoundParametersOODSamples)),
		CombinationRandomness: make([][]frontend.Variable, len(circuit.RoundParametersOODSamples)),
	}
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

		x_leftChild := api.Select(dir, leafSiblingHash, claimedLeafHash)
		x_rightChild := api.Select(dir, claimedLeafHash, leafSiblingHash)

		currentHash := sc.Compress(x_leftChild, x_rightChild)

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

type InitialSumcheckData struct {
	InitialOODQueries            []frontend.Variable
	InitialCombinationRandomness []frontend.Variable
}

func initialSumcheck(
	api frontend.API,
	circuit *Circuit,
	arthur gnark_nimue.Arthur,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
) (InitialSumcheckData, frontend.Variable, []frontend.Variable, error) {
	if err := FillInAndVerifyRootHash(0, api, uapi, sc, circuit, arthur); err != nil {
		return InitialSumcheckData{}, nil, nil, err
	}

	initialOODQueries, initialOODAnswers, err := FillInOODPointsAndAnswers(circuit.CommittmentOODSamples, arthur)
	if err != nil {
		return InitialSumcheckData{}, nil, nil, err
	}

	initialCombinationRandomness, err := GenerateCombinationRandomness(api, arthur, circuit.CommittmentOODSamples+len(circuit.LinearStatementEvaluations))
	if err != nil {
		return InitialSumcheckData{}, nil, nil, err
	}

	OODAnswersAndStatmentEvaluations := append(initialOODAnswers, circuit.LinearStatementEvaluations...)
	lastEval := utilities.DotProduct(api, initialCombinationRandomness, OODAnswersAndStatmentEvaluations)

	initialSumcheckFoldingRandomness, lastEval, err := runSumcheckRounds(api, lastEval, arthur, circuit.FoldingFactorArray[0], 3)
	if err != nil {
		return InitialSumcheckData{}, nil, nil, err
	}

	return InitialSumcheckData{
		InitialOODQueries:            initialOODQueries,
		InitialCombinationRandomness: initialCombinationRandomness,
	}, lastEval, initialSumcheckFoldingRandomness, nil
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

func FillInSumcheckPolynomialsAndRandomnessAndRunPoW(NVars int, arthur gnark_nimue.Arthur, api frontend.API, sc *skyscraper.Skyscraper, NpowBits int) ([][]frontend.Variable, []frontend.Variable, error) {
	mainRoundSumcheckPolynomials := make([][]frontend.Variable, NVars)
	sumcheckRandomness := make([]frontend.Variable, NVars)

	for i := range NVars {
		mainRoundSumcheckPolynomials[i] = make([]frontend.Variable, 3) // Sumcheck polynomial in the evaluations form
		sumcheckRanomnessTemp := make([]frontend.Variable, 1)          // Sumcheck folding randomness

		if err := arthur.FillNextScalars(mainRoundSumcheckPolynomials[i]); err != nil {
			return nil, nil, err
		}

		if err := arthur.FillChallengeScalars(sumcheckRanomnessTemp); err != nil {
			return nil, nil, err
		}

		sumcheckRandomness[i] = sumcheckRanomnessTemp[0]
		if err := RunPoW(api, sc, arthur, NpowBits); err != nil {
			return nil, nil, err
		}
	}

	return mainRoundSumcheckPolynomials, sumcheckRandomness, nil
}

func GenerateStirChallengePoints(api frontend.API, arthur gnark_nimue.Arthur, NQueries int, leafIndexes []uints.U64, domainSize int, circuit *Circuit, uapi *uints.BinaryField[uints.U64], expDomainGenerator frontend.Variable, roundIndex int) ([]frontend.Variable, error) {
	finalIndexes, err := GetStirChallenges(api, *circuit, arthur, NQueries, domainSize, roundIndex)
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

func runSumcheckRounds(
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
	circuit *Circuit,
	initialSumcheckData InitialSumcheckData,
	mainRoundData MainRoundData,
	sp_rand []frontend.Variable,
	totalFoldingRandomness []frontend.Variable,
) frontend.Variable {
	foldingRandomnessReversed := utilities.Reverse(totalFoldingRandomness)
	numberVars := circuit.MVParamsNumberOfVariables

	value := frontend.Variable(0)
	for j := range initialSumcheckData.InitialOODQueries {
		value = api.Add(value, api.Mul(initialSumcheckData.InitialCombinationRandomness[j], utilities.EqPolyOutside(api, utilities.ExpandFromUnivariate(api, initialSumcheckData.InitialOODQueries[j], numberVars), foldingRandomnessReversed)))
	}

	matrixExtensionEvals := evaluateR1CSMatrixExtension(api, circuit, sp_rand, foldingRandomnessReversed)

	for j := range circuit.LinearStatementValuesAtPoints {
		value = api.Add(value, api.Mul(initialSumcheckData.InitialCombinationRandomness[len(initialSumcheckData.InitialOODQueries)+j], matrixExtensionEvals[j]))
	}

	for r := range mainRoundData.OODPoints {
		numberVars -= circuit.FoldingFactorArray[r]
		newTmpArr := append(mainRoundData.OODPoints[r], mainRoundData.StirChallengesPoints[r]...)

		sumOfClaims := frontend.Variable(0)
		for i := range newTmpArr {
			point := utilities.ExpandFromUnivariate(api, newTmpArr[i], numberVars)
			sumOfClaims = api.Add(sumOfClaims, api.Mul(utilities.EqPolyOutside(api, point, foldingRandomnessReversed[0:numberVars]), mainRoundData.CombinationRandomness[r][i]))
		}
		value = api.Add(value, sumOfClaims)
	}

	return value
}

func ComputeFoldsHelped(api frontend.API, circuit *Circuit, initialSumcheckFoldingRandomness []frontend.Variable, mainRoundFoldingRandomness [][]frontend.Variable) [][]frontend.Variable {
	foldingRandomness := append([][]frontend.Variable{initialSumcheckFoldingRandomness}, mainRoundFoldingRandomness...)
	result := make([][]frontend.Variable, len(circuit.Leaves))

	for i := range len(circuit.Leaves) {
		result[i] = make([]frontend.Variable, len(circuit.Leaves[i]))
		for j := range circuit.Leaves[i] {
			result[i][j] = utilities.MultivarPoly(circuit.Leaves[i][j], foldingRandomness[i], api)
		}
	}

	return result
}

func ComputeFoldsFull(api frontend.API, circuit *Circuit) [][]frontend.Variable {
	return nil
}

func ComputeFolds(api frontend.API, circuit *Circuit, initialSumcheckFoldingRandomness []frontend.Variable, mainRoundFoldingRandomness [][]frontend.Variable) [][]frontend.Variable {
	if circuit.FoldOptimisation {
		return ComputeFoldsHelped(api, circuit, initialSumcheckFoldingRandomness, mainRoundFoldingRandomness)
	} else {
		return ComputeFoldsFull(api, circuit)
	}
}

func SumcheckForR1CSIOP(api frontend.API, arthur gnark_nimue.Arthur, circuit *Circuit) ([]frontend.Variable, []frontend.Variable, frontend.Variable, error) {
	t_rand := make([]frontend.Variable, circuit.LogNumConstraints)
	err := arthur.FillChallengeScalars(t_rand)
	if err != nil {
		return nil, nil, nil, err
	}

	sp_rand := make([]frontend.Variable, circuit.LogNumConstraints)
	savedValForSumcheck := frontend.Variable(0)

	sp_rand_temp := make([]frontend.Variable, 1)
	for i := 0; i < circuit.LogNumConstraints; i++ {
		sp := make([]frontend.Variable, 4)
		if err = arthur.FillNextScalars(sp); err != nil {
			return nil, nil, nil, err
		}
		if err = arthur.FillChallengeScalars(sp_rand_temp); err != nil {
			return nil, nil, nil, err
		}
		sp_rand[i] = sp_rand_temp[0]
		sumcheckVal := api.Add(utilities.UnivarPoly(api, sp, []frontend.Variable{0})[0], utilities.UnivarPoly(api, sp, []frontend.Variable{1})[0])
		api.AssertIsEqual(sumcheckVal, savedValForSumcheck)
		savedValForSumcheck = utilities.UnivarPoly(api, sp, []frontend.Variable{sp_rand[i]})[0]
	}

	return t_rand, sp_rand, savedValForSumcheck, nil
}

func FillInAndVerifyRootHash(roundNum int, api frontend.API, uapi *uints.BinaryField[uints.U64], sc *skyscraper.Skyscraper, circuit *Circuit, arthur gnark_nimue.Arthur) error {
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

func generateFinalCoefficientsAndRandomnessPoints(api frontend.API, arthur gnark_nimue.Arthur, circuit *Circuit, uapi *uints.BinaryField[uints.U64], sc *skyscraper.Skyscraper, domainSize int, expDomainGenerator frontend.Variable) ([]frontend.Variable, []frontend.Variable, error) {
	finalCoefficients := make([]frontend.Variable, 1<<circuit.FinalSumcheckRounds)
	if err := arthur.FillNextScalars(finalCoefficients); err != nil {
		return nil, nil, err
	}
	finalRandomnessPoints, err := GenerateStirChallengePoints(api, arthur, circuit.FinalQueries, circuit.LeafIndexes[len(circuit.LeafIndexes)-1], domainSize, circuit, uapi, expDomainGenerator, len(circuit.FoldingFactorArray)-1)
	if err != nil {
		return nil, nil, err
	}
	if err := RunPoW(api, sc, arthur, circuit.FinalPowBits); err != nil {
		return nil, nil, err
	}
	return finalCoefficients, finalRandomnessPoints, nil
}

func initializeComponents(api frontend.API, circuit *Circuit) (*skyscraper.Skyscraper, gnark_nimue.Arthur, *uints.BinaryField[uints.U64], error) {
	sc := skyscraper.NewSkyscraper(api, 2)
	arthur, err := gnark_nimue.NewSkyscraperArthur(api, sc, circuit.IO, circuit.Transcript[:])
	if err != nil {
		return nil, nil, nil, err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, nil, nil, err
	}
	return sc, arthur, uapi, nil
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

func mustBigInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid big.Int string: " + s)
	}
	return n
}

func evaluateR1CSMatrixExtension(api frontend.API, circuit *Circuit, rowRand []frontend.Variable, colRand []frontend.Variable) []frontend.Variable {
	ansA := frontend.Variable(0)
	ansB := frontend.Variable(0)
	ansC := frontend.Variable(0)

	rowEval := calculateEQOverBooleanHypercube(api, rowRand)
	colEval := calculateEQOverBooleanHypercube(api, colRand)

	for i := range len(circuit.MatrixA) {
		ansA = api.Add(ansA, api.Mul(circuit.MatrixA[i].value, api.Mul(rowEval[circuit.MatrixA[i].row], colEval[circuit.MatrixA[i].column])))
	}
	for i := range circuit.MatrixB {
		ansB = api.Add(ansB, api.Mul(circuit.MatrixB[i].value, api.Mul(rowEval[circuit.MatrixB[i].row], colEval[circuit.MatrixB[i].column])))
	}
	for i := range circuit.MatrixC {
		ansC = api.Add(ansC, api.Mul(circuit.MatrixC[i].value, api.Mul(rowEval[circuit.MatrixC[i].row], colEval[circuit.MatrixC[i].column])))
	}

	return []frontend.Variable{ansA, ansB, ansC}
}

func calculateEQOverBooleanHypercube(api frontend.API, r []frontend.Variable) []frontend.Variable {
	ans := []frontend.Variable{frontend.Variable(1)}

	for i := len(r) - 1; i >= 0; i-- {
		x := r[i]
		left := make([]frontend.Variable, len(ans))
		right := make([]frontend.Variable, len(ans))

		for j, y := range ans {
			left[j] = api.Mul(y, api.Sub(1, x))
			right[j] = api.Mul(y, x)
		}

		ans = append(left, right...)
	}

	return ans
}

type MatrixCell struct {
	row    int
	column int
	value  *big.Int
}
