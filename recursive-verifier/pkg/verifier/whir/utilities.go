package whir

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"

	"reilabs/whir-verifier-circuit/pkg/crypto/polynomial"
	"reilabs/whir-verifier-circuit/pkg/verifier/types"
)

func verifyMerkleTreeProofs(api frontend.API, uapi *uints.BinaryField[uints.U64], sc *skyscraper.Skyscraper, leafIndexes []uints.U64, leaves [][]frontend.Variable, leafSiblingHashes []frontend.Variable, authPaths [][]frontend.Variable, rootHash frontend.Variable) error {
	numOfLeavesProved := len(leaves)
	for i := 0; i < numOfLeavesProved; i++ {
		treeHeight := len(authPaths[i]) + 1
		leafIndexBits := api.ToBinary(uapi.ToValue(leafIndexes[i]), treeHeight)
		leafSiblingHash := leafSiblingHashes[i]

		claimedLeafHash := sc.CompressV2(leaves[i][0], leaves[i][1])
		for x := 0; x < len(leaves[i])-2; x++ {
			claimedLeafHash = sc.CompressV2(claimedLeafHash, leaves[i][x+2])
		}

		dir := leafIndexBits[0]

		xLeftChild := api.Select(dir, leafSiblingHash, claimedLeafHash)
		xRightChild := api.Select(dir, claimedLeafHash, leafSiblingHash)

		currentHash := sc.CompressV2(xLeftChild, xRightChild)

		for level := 1; level < treeHeight; level++ {
			indexBit := leafIndexBits[level]

			siblingHash := authPaths[i][level-1]

			dir := api.And(indexBit, 1)
			left := api.Select(dir, siblingHash, currentHash)
			right := api.Select(dir, currentHash, siblingHash)

			currentHash = sc.CompressV2(left, right)
		}
		api.AssertIsEqual(currentHash, rootHash)
	}
	return nil
}

func generateEmptyMainRoundData(params types.WHIRParams) types.MainRoundData {
	return types.MainRoundData{
		OODPoints:             make([][]frontend.Variable, len(params.RoundParametersOODSamples)),
		StirChallengesPoints:  make([][]frontend.Variable, len(params.RoundParametersOODSamples)),
		CombinationRandomness: make([][]frontend.Variable, len(params.RoundParametersOODSamples)),
	}
}

func fillInOODPointsAndAnswers(numberOfOODPoints int, arthur gnarkNimue.Arthur) ([]frontend.Variable, []frontend.Variable, error) {
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

func runWhirSumcheckRounds(
	api frontend.API,
	lastEval frontend.Variable,
	arthur gnarkNimue.Arthur,
	foldingFactor int,
	polynomialDegree int,
) ([]frontend.Variable, frontend.Variable, error) {
	sumcheckPolynomial := make([]frontend.Variable, polynomialDegree)
	foldingRandomness := make([]frontend.Variable, foldingFactor)
	foldingRandomnessTemp := make([]frontend.Variable, 1)

	for i := 0; i < foldingFactor; i++ {
		if err := arthur.FillNextScalars(sumcheckPolynomial); err != nil {
			return nil, nil, err
		}
		if err := arthur.FillChallengeScalars(foldingRandomnessTemp); err != nil {
			return nil, nil, err
		}
		foldingRandomness[i] = foldingRandomnessTemp[0]
		checkSumOverBool(api, lastEval, sumcheckPolynomial)
		lastEval = polynomial.EvaluateQuadraticFromEvaluations(api, sumcheckPolynomial, foldingRandomness[i])
	}
	return foldingRandomness, lastEval, nil
}

func computeWPoly(
	api frontend.API,
	params types.WHIRParams,
	initialData types.InitialSumcheckData,
	mainRoundData types.MainRoundData,
	totalFoldingRandomness []frontend.Variable,
	linearStatementValuesAtPoints []frontend.Variable,
	evaluationPoints [][]frontend.Variable,
) frontend.Variable {
	numberVars := params.MVParamsNumberOfVariables

	eqValues := []frontend.Variable{}
	for _, evaluationPoint := range evaluationPoints {
		eqValues = append(eqValues, calculateEQ(api, totalFoldingRandomness, evaluationPoint))
	}

	value := frontend.Variable(0)
	for j := range initialData.InitialOODQueries {
		value = api.Add(
			value,
			api.Mul(
				initialData.InitialCombinationRandomness[j],
				polynomial.EqualityOutside(api, polynomial.ExpandFromUnivariate(api, initialData.InitialOODQueries[j], numberVars), totalFoldingRandomness),
			),
		)
	}

	for j, linearStatementValueAtPoint := range linearStatementValuesAtPoints {
		value = api.Add(value, api.Mul(initialData.InitialCombinationRandomness[len(initialData.InitialOODQueries)+j], linearStatementValueAtPoint))
	}

	for j, eqValue := range eqValues {
		value = api.Add(value, api.Mul(initialData.InitialCombinationRandomness[len(initialData.InitialOODQueries)+len(linearStatementValuesAtPoints)+j], eqValue))
	}

	for r := range mainRoundData.OODPoints {
		numberVars -= params.FoldingFactorArray[r]
		newTmpArr := append(mainRoundData.OODPoints[r], mainRoundData.StirChallengesPoints[r]...)

		sumOfClaims := frontend.Variable(0)
		for i := range newTmpArr {
			point := polynomial.ExpandFromUnivariate(api, newTmpArr[i], numberVars)
			sumOfClaims = api.Add(
				sumOfClaims,
				api.Mul(
					polynomial.EqualityOutside(api, point, totalFoldingRandomness[0:numberVars]),
					mainRoundData.CombinationRandomness[r][i],
				),
			)
		}
		value = api.Add(value, sumOfClaims)
	}

	return value
}

//nolint:unused
func fillInAndVerifyRootHash(
	roundNum int,
	api frontend.API,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
	circuit types.Merkle,
	arthur gnarkNimue.Arthur,
) error {
	rootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(rootHash); err != nil {
		return err
	}
	err := verifyMerkleTreeProofs(api, uapi, sc, circuit.LeafIndexes[roundNum], circuit.Leaves[roundNum], circuit.LeafSiblingHashes[roundNum], circuit.AuthPaths[roundNum], rootHash[0])
	if err != nil {
		return err
	}
	return nil
}

func computeFold(leaves [][]frontend.Variable, foldingRandomness []frontend.Variable, api frontend.API) []frontend.Variable {
	computedFold := make([]frontend.Variable, len(leaves))
	for j := range leaves {
		computedFold[j] = polynomial.Multivar(api, leaves[j], foldingRandomness)
	}
	return computedFold
}

func calculateShiftValue(oodAnswers []frontend.Variable, combinationRandomness []frontend.Variable, computedFold []frontend.Variable, api frontend.API) frontend.Variable {
	return polynomial.DotProduct(api, append(oodAnswers, computedFold...), combinationRandomness)
}

func checkSumOverBool(api frontend.API, value frontend.Variable, polyEvals []frontend.Variable) {
	sum := api.Add(polyEvals[0], polyEvals[1])
	api.AssertIsEqual(value, sum)
}

func exponent(api frontend.API, uapi *uints.BinaryField[uints.U64], base frontend.Variable, exp uints.U64) frontend.Variable {
	result := frontend.Variable(1)
	binary := api.ToBinary(uapi.ToValue(exp))
	acc := base
	for i := range binary {
		result = api.Select(binary[i], api.Mul(result, acc), result)
		acc = api.Mul(acc, acc)
	}
	return result
}

func reverseVariables(values []frontend.Variable) []frontend.Variable {
	res := make([]frontend.Variable, len(values))
	copy(res, values)
	for i, j := 0, len(res)-1; i < j; i, j = i+1, j-1 {
		res[i], res[j] = res[j], res[i]
	}
	return res
}

func calculateEQ(api frontend.API, alphas []frontend.Variable, r []frontend.Variable) frontend.Variable {
	ans := frontend.Variable(1)
	for i, alpha := range alphas {
		ans = api.Mul(
			ans,
			api.Add(
				api.Mul(alpha, r[i]),
				api.Mul(api.Sub(frontend.Variable(1), alpha), api.Sub(frontend.Variable(1), r[i])),
			),
		)
	}
	return ans
}
