package circuit

import (
	"math/big"
	"reilabs/whir-verifier-circuit/app/utilities"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

func New_whir_params(cfg WHIRConfig) WHIRParams {
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
		BatchSize:                            cfg.BatchSize,
	}
}

func RunZKWhir(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
	circuit Merkle,
	firstRound Merkle,
	whirParams WHIRParams,
	linearStatementEvaluations [][]frontend.Variable,
	linearStatementValuesAtPoints []frontend.Variable,
	batchingRandomness frontend.Variable,
	initialOODQueries []frontend.Variable,
	initialOODAnswers [][]frontend.Variable,
	rootHashes frontend.Variable,
) (totalFoldingRandomness []frontend.Variable, err error) {

	initialOODs := oodAnswers(api, initialOODAnswers, batchingRandomness)
	// batchSizeLen := whirParams.BatchSize

	initialSumcheckData, lastEval, initialSumcheckFoldingRandomness, err := initialSumcheck(api, arthur, batchingRandomness, initialOODQueries, initialOODs, whirParams, linearStatementEvaluations)
	if err != nil {
		return
	}

	copyOfFirstLeaves := make([][][]frontend.Variable, len(firstRound.Leaves))
	for i := range len(firstRound.Leaves) {
		copyOfFirstLeaves[i] = make([][]frontend.Variable, len(firstRound.Leaves[i]))
		for j := range len(firstRound.Leaves[i]) {
			copyOfFirstLeaves[i][j] = make([]frontend.Variable, len(firstRound.Leaves[i][j]))
			for k := range len(firstRound.Leaves[i][j]) {
				copyOfFirstLeaves[i][j][k] = firstRound.Leaves[i][j][k]
			}
		}
	}

	roundAnswers := make([][][]frontend.Variable, len(circuit.Leaves)+1)

	foldSize := 1 << whirParams.FoldingFactorArray[0]
	collapsed := rlcBatchedLeaves(api, firstRound.Leaves[0], foldSize, whirParams.BatchSize, batchingRandomness)
	roundAnswers[0] = collapsed

	for i := range len(circuit.Leaves) {
		roundAnswers[i+1] = circuit.Leaves[i]
	}

	computedFold := computeFold(collapsed, initialSumcheckFoldingRandomness, api)

	mainRoundData := generateEmptyMainRoundData(whirParams)
	expDomainGenerator := utilities.Exponent(api, uapi, whirParams.StartingDomainBackingDomainGenerator, uints.NewU64(uint64(1<<whirParams.FoldingFactorArray[0])))
	domainSize := whirParams.DomainSize

	totalFoldingRandomness = initialSumcheckFoldingRandomness

	rootHashList := make([]frontend.Variable, len(whirParams.RoundParametersOODSamples))

	for r := range whirParams.ParamNRounds {
		rootHash := make([]frontend.Variable, 1)
		if err = arthur.FillNextScalars(rootHash); err != nil {
			return
		}
		var roundOODAnswers []frontend.Variable

		rootHashList[r] = rootHash[0]
		mainRoundData.OODPoints[r], roundOODAnswers, err = fillInOODPointsAndAnswers(whirParams.RoundParametersOODSamples[r], arthur)
		if err != nil {
			return
		}

		if err = RunPoW(api, sc, arthur, whirParams.PowBits[r]); err != nil {
			return
		}

		mainRoundData.StirChallengesPoints[r], err = getStirChallenges(api, arthur, whirParams.RoundParametersNumOfQueries[r], domainSize, 1<<whirParams.FoldingFactorArray[r])
		if err != nil {
			return
		}

		if r == 0 {
			err = verifyMerkleTreeProofs(api, uapi, sc, firstRound.LeafIndexes[0], firstRound.Leaves[0], firstRound.LeafSiblingHashes[0], firstRound.AuthPaths[0], rootHashes)
			if err != nil {
				return
			}

			err = utilities.IsSubset(api, uapi, arthur, mainRoundData.StirChallengesPoints[r], firstRound.LeafIndexes[0])
			if err != nil {
				return
			}

			mainRoundData.StirChallengesPoints[r] = make([]frontend.Variable, len(firstRound.LeafIndexes[r]))
			for index := range firstRound.LeafIndexes[r] {
				mainRoundData.StirChallengesPoints[r][index] = utilities.Exponent(api, uapi, expDomainGenerator, firstRound.LeafIndexes[r][index])
			}
		} else {
			err = verifyMerkleTreeProofs(api, uapi, sc, circuit.LeafIndexes[r-1], roundAnswers[r], circuit.LeafSiblingHashes[r-1], circuit.AuthPaths[r-1], rootHashList[r-1])
			if err != nil {
				return
			}
			err = utilities.IsSubset(api, uapi, arthur, mainRoundData.StirChallengesPoints[r], circuit.LeafIndexes[r-1])
			if err != nil {
				return
			}
			mainRoundData.StirChallengesPoints[r] = make([]frontend.Variable, len(circuit.LeafIndexes[r-1]))
			for index := range circuit.LeafIndexes[r-1] {
				mainRoundData.StirChallengesPoints[r][index] = utilities.Exponent(api, uapi, expDomainGenerator, circuit.LeafIndexes[r-1][index])
			}
		}

		mainRoundData.CombinationRandomness[r], err = GenerateCombinationRandomness(api, arthur, len(mainRoundData.OODPoints[r])+len(computedFold))
		if err != nil {
			return
		}

		lastEval = api.Add(lastEval, calculateShiftValue(roundOODAnswers, mainRoundData.CombinationRandomness[r], computedFold, api))

		var roundFoldingRandomness []frontend.Variable
		roundFoldingRandomness, lastEval, err = runWhirSumcheckRounds(api, lastEval, arthur, whirParams.FoldingFactorArray[r], 3)
		if err != nil {
			return
		}

		computedFold = computeFold(circuit.Leaves[r], roundFoldingRandomness, api)
		totalFoldingRandomness = append(totalFoldingRandomness, roundFoldingRandomness...)

		domainSize /= 2
		expDomainGenerator = api.Mul(expDomainGenerator, expDomainGenerator)
	}

	finalCoefficients, finalRandomnessPoints, err := generateFinalCoefficientsAndRandomnessPoints(api, arthur, whirParams, circuit, uapi, sc, domainSize, expDomainGenerator)
	if err != nil {
		return
	}

	finalEvaluations := utilities.UnivarPoly(api, finalCoefficients, finalRandomnessPoints)

	for foldIndex := range computedFold {
		api.AssertIsEqual(computedFold[foldIndex], finalEvaluations[foldIndex])
	}

	finalSumcheckRandomness, lastEval, err := runWhirSumcheckRounds(api, lastEval, arthur, whirParams.FinalSumcheckRounds, 3)
	if err != nil {
		return
	}

	totalFoldingRandomness = append(totalFoldingRandomness, finalSumcheckRandomness...)

	if whirParams.FinalFoldingPowBits > 0 {
		_, _, err = utilities.PoW(api, sc, arthur, whirParams.FinalFoldingPowBits)
		if err != nil {
			return
		}
	}

	totalFoldingRandomness = utilities.Reverse(totalFoldingRandomness)

	evaluationOfWPoly := computeWPoly(
		api,
		whirParams,
		initialSumcheckData,
		mainRoundData,
		totalFoldingRandomness,
		linearStatementValuesAtPoints,
	)

	api.AssertIsEqual(
		lastEval,
		api.Mul(evaluationOfWPoly, utilities.MultivarPoly(finalCoefficients, finalSumcheckRandomness, api)),
	)

	return totalFoldingRandomness, nil
}

//nolint:unused
func runWhir(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
	circuit Merkle,
	whirParams WHIRParams,
	linearStatementEvaluations []frontend.Variable,
	linearStatementValuesAtPoints []frontend.Variable,
) (totalFoldingRandomness []frontend.Variable, err error) {
	if err = fillInAndVerifyRootHash(0, api, uapi, sc, circuit, arthur); err != nil {
		return
	}

	initialOODQueries, initialOODAnswers, tempErr := fillInOODPointsAndAnswers(whirParams.CommittmentOODSamples, arthur)
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
		if err = fillInAndVerifyRootHash(r+1, api, uapi, sc, circuit, arthur); err != nil {
			return
		}

		var roundOODAnswers []frontend.Variable
		mainRoundData.OODPoints[r], roundOODAnswers, err = fillInOODPointsAndAnswers(whirParams.RoundParametersOODSamples[r], arthur)
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

	evaluationOfVPoly := computeWPoly(
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

func RunPoW(api frontend.API, sc *skyscraper.Skyscraper, arthur gnarkNimue.Arthur, difficulty int) error {
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
	arthur gnarkNimue.Arthur,
	NQueries int,
	leafIndexes []uints.U64,
	domainSize int,
	uapi *uints.BinaryField[uints.U64],
	expDomainGenerator frontend.Variable,
	foldingFactor int,
) ([]frontend.Variable, error) {
	foldingFactorPower := 1 << foldingFactor
	finalIndexes, err := getStirChallenges(api, arthur, NQueries, domainSize, foldingFactorPower)
	if err != nil {
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

func GenerateCombinationRandomness(api frontend.API, arthur gnarkNimue.Arthur, randomnessLength int) ([]frontend.Variable, error) {
	combRandomnessGen := make([]frontend.Variable, 1)
	if err := arthur.FillChallengeScalars(combRandomnessGen); err != nil {
		return nil, err
	}

	combinationRandomness := utilities.ExpandRandomness(api, combRandomnessGen[0], randomnessLength)
	return combinationRandomness, nil

}
