package main

import (
	"fmt"
	"log"
	"math/bits"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"

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
	foldedDomainSize := domainSize / (1 << circuit.WHIRCircuitCol.FoldingFactorArray[roundIndex])
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
	LinearStatementValuesAtPoints []frontend.Variable
	LinearStatementEvaluations    []frontend.Variable
	LogNumConstraints             int
	WHIRCircuitCol                WHIRCircuit
	// Public Input
	IO         []byte
	Transcript []uints.U8 `gnark:",public"`
}

type WHIRCircuit struct {
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
	Leaves                               [][][]frontend.Variable
	LeafIndexes                          [][]uints.U64
	LeafSiblingHashes                    [][][]uints.U8
	AuthPaths                            [][][][]uints.U8
}

type MainRoundData struct {
	OODPoints             [][]frontend.Variable
	StirChallengesPoints  [][]frontend.Variable
	CombinationRandomness [][]frontend.Variable
}

func generateEmptyMainRoundData(circuit *Circuit) MainRoundData {
	return MainRoundData{
		OODPoints:             make([][]frontend.Variable, len(circuit.WHIRCircuitCol.RoundParametersOODSamples)),
		StirChallengesPoints:  make([][]frontend.Variable, len(circuit.WHIRCircuitCol.RoundParametersOODSamples)),
		CombinationRandomness: make([][]frontend.Variable, len(circuit.WHIRCircuitCol.RoundParametersOODSamples)),
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
	circuit *Circuit,
	initialData InitialSumcheckData,
	mainRoundData MainRoundData,
	sp_rand []frontend.Variable,
	totalFoldingRandomness []frontend.Variable,
) frontend.Variable {
	foldingRandomnessReversed := utilities.Reverse(totalFoldingRandomness)
	numberVars := circuit.WHIRCircuitCol.MVParamsNumberOfVariables

	value := frontend.Variable(0)
	for j := range initialData.InitialOODQueries {
		value = api.Add(value, api.Mul(initialData.InitialCombinationRandomness[j], utilities.EqPolyOutside(api, utilities.ExpandFromUnivariate(api, initialData.InitialOODQueries[j], numberVars), foldingRandomnessReversed)))
	}

	for j, linearStatementValueAtPoint := range circuit.LinearStatementValuesAtPoints {
		value = api.Add(value, api.Mul(initialData.InitialCombinationRandomness[len(initialData.InitialOODQueries)+j], linearStatementValueAtPoint))
	}

	for r := range mainRoundData.OODPoints {
		numberVars -= circuit.WHIRCircuitCol.FoldingFactorArray[r]
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
	err := VerifyMerkleTreeProofs(api, uapi, sc, circuit.WHIRCircuitCol.LeafIndexes[roundNum], circuit.WHIRCircuitCol.Leaves[roundNum], circuit.WHIRCircuitCol.LeafSiblingHashes[roundNum], circuit.WHIRCircuitCol.AuthPaths[roundNum], rootHash[0])
	if err != nil {
		return err
	}
	return nil
}

func generateFinalCoefficientsAndRandomnessPoints(api frontend.API, arthur gnark_nimue.Arthur, circuit *Circuit, uapi *uints.BinaryField[uints.U64], sc *skyscraper.Skyscraper, domainSize int, expDomainGenerator frontend.Variable) ([]frontend.Variable, []frontend.Variable, error) {
	finalCoefficients := make([]frontend.Variable, 1<<circuit.WHIRCircuitCol.FinalSumcheckRounds)
	if err := arthur.FillNextScalars(finalCoefficients); err != nil {
		return nil, nil, err
	}
	finalRandomnessPoints, err := GenerateStirChallengePoints(api, arthur, circuit.WHIRCircuitCol.FinalQueries, circuit.WHIRCircuitCol.LeafIndexes[len(circuit.WHIRCircuitCol.LeafIndexes)-1], domainSize, circuit, uapi, expDomainGenerator, len(circuit.WHIRCircuitCol.FoldingFactorArray)-1)
	if err != nil {
		return nil, nil, err
	}
	if err := RunPoW(api, sc, arthur, circuit.WHIRCircuitCol.FinalPowBits); err != nil {
		return nil, nil, err
	}
	return finalCoefficients, finalRandomnessPoints, nil
}

func initializeComponents(api frontend.API, circuit *Circuit) (*skyscraper.Skyscraper, gnark_nimue.Arthur, *uints.BinaryField[uints.U64], error) {
	sc := skyscraper.NewSkyscraper(api, 2)
	arthur, err := gnark_nimue.NewSkyscraperArthur(api, sc, circuit.IO, circuit.Transcript[:], true)
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

// func mustBigInt(s string) *big.Int {
// 	n, ok := new(big.Int).SetString(s, 10)
// 	if !ok {
// 		panic("invalid big.Int string: " + s)
// 	}
// 	return n
// }

// func calculateEQOverBooleanHypercube(api frontend.API, r []frontend.Variable) []frontend.Variable {
// 	ans := []frontend.Variable{frontend.Variable(1)}

// 	for i := len(r) - 1; i >= 0; i-- {
// 		x := r[i]
// 		left := make([]frontend.Variable, len(ans))
// 		right := make([]frontend.Variable, len(ans))

// 		for j, y := range ans {
// 			left[j] = api.Mul(y, api.Sub(1, x))
// 			right[j] = api.Mul(y, x)
// 		}

// 		ans = append(left, right...)
// 	}

// 	return ans
// }

func keys_from_files(pkPath string, vkPath string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pkFile, err := os.Open(pkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open proving key file: %w", err)
	}
	defer func(pkFile *os.File) {
		err := pkFile.Close()
		if err != nil {
			log.Printf("failed to close proving key file: %v", err)
		}
	}(pkFile)

	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(pkFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to restore proving key: %w", err)

	}

	vkFile, err := os.Open(vkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open verifying key file: %w", err)
	}
	defer func(vkFile *os.File) {
		err := vkFile.Close()
		if err != nil {
			log.Printf("failed to close verifying key file: %v", err)
		}
	}(vkFile)

	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to restore verifying key: %w", err)
	}

	return pk, vk, nil
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
		sumcheckVal := api.Add(
			utilities.UnivarPoly(api, sumcheckPolynomial, []frontend.Variable{0})[0],
			utilities.UnivarPoly(api, sumcheckPolynomial, []frontend.Variable{1})[0],
		)
		api.AssertIsEqual(sumcheckVal, lastEval)
		lastEval = utilities.UnivarPoly(api, sumcheckPolynomial, []frontend.Variable{foldingRandomness[i]})[0]
	}
	return foldingRandomness, lastEval, nil
}
