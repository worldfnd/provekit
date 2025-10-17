package whir

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"

	"reilabs/whir-verifier-circuit/pkg/crypto/polynomial"
	"reilabs/whir-verifier-circuit/pkg/verifier/merkle"
	"reilabs/whir-verifier-circuit/pkg/verifier/types"
)

func RunZKWhir(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
	circuit types.Merkle,
	firstRound types.Merkle,
	whirParams types.WHIRParams,
	linearStatementEvaluations [][]frontend.Variable,
	linearStatementValuesAtPoints []frontend.Variable,

	commitment types.Commitment,

	// batchingRandomness frontend.Variable,
	// initialOODQueries []frontend.Variable,
	// initialOODAnswers [][]frontend.Variable,
	// rootHashes frontend.Variable,

	evaluationStatementClaimedValues [][]frontend.Variable,
	evaluationPoints [][]frontend.Variable,
) (totalFoldingRandomness []frontend.Variable, err error) {
	initialOODs := merkle.OODAnswers(api, commitment.InitialOODAnswers, commitment.BatchingRandomness)

	initialSumcheckData, lastEval, initialSumcheckFoldingRandomness, err := merkle.InitialSumcheck(api, arthur, commitment.BatchingRandomness, commitment.InitialOODQueries, initialOODs, whirParams, linearStatementEvaluations, evaluationStatementClaimedValues)
	if err != nil {
		return
	}

	roundAnswers := make([][][]frontend.Variable, len(circuit.Leaves)+1)

	foldSize := 1 << whirParams.FoldingFactorArray[0]
	collapsed := merkle.RLCBatchedLeaves(api, firstRound.Leaves[0], foldSize, whirParams.BatchSize, commitment.BatchingRandomness)
	roundAnswers[0] = collapsed

	for i := range circuit.Leaves {
		roundAnswers[i+1] = circuit.Leaves[i]
	}

	computedFold := computeFold(collapsed, initialSumcheckFoldingRandomness, api)

	mainRoundData := generateEmptyMainRoundData(whirParams)
	expDomainGenerator := exponent(api, uapi, whirParams.StartingDomainBackingDomainGenerator, uints.NewU64(uint64(1<<whirParams.FoldingFactorArray[0])))
	domainSize := whirParams.DomainSize

	totalFoldingRandomness = initialSumcheckFoldingRandomness

	rootHashList := make([]frontend.Variable, len(whirParams.RoundParametersOODSamples))

	for r := 0; r < whirParams.ParamNRounds; r++ {
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

		if err = merkle.RunPoW(api, sc, arthur, whirParams.PowBits[r]); err != nil {
			return
		}

		if r == 0 {
			mainRoundData.StirChallengesPoints[r], err = merkle.GenerateStirChallengePoints(
				api,
				arthur,
				whirParams.RoundParametersNumOfQueries[r],
				firstRound.LeafIndexes[0],
				domainSize,
				uapi,
				expDomainGenerator,
				whirParams.FoldingFactorArray[r],
			)
			if err != nil {
				return
			}
			err = verifyMerkleTreeProofs(api, uapi, sc, firstRound.LeafIndexes[0], firstRound.Leaves[0], firstRound.LeafSiblingHashes[0], firstRound.AuthPaths[0], commitment.RootHash)
			if err != nil {
				return
			}
		} else {
			mainRoundData.StirChallengesPoints[r], err = merkle.GenerateStirChallengePoints(
				api,
				arthur,
				whirParams.RoundParametersNumOfQueries[r],
				circuit.LeafIndexes[r-1],
				domainSize,
				uapi,
				expDomainGenerator,
				whirParams.FoldingFactorArray[r],
			)
			if err != nil {
				return
			}
			err = verifyMerkleTreeProofs(api, uapi, sc, circuit.LeafIndexes[r-1], roundAnswers[r], circuit.LeafSiblingHashes[r-1], circuit.AuthPaths[r-1], rootHashList[r-1])
			if err != nil {
				return
			}
		}

		mainRoundData.CombinationRandomness[r], err = merkle.GenerateCombinationRandomness(api, arthur, len(mainRoundData.OODPoints[r])+len(computedFold))
		if err != nil {
			return
		}

		lastEval = api.Add(lastEval, calculateShiftValue(roundOODAnswers, mainRoundData.CombinationRandomness[r], computedFold, api))

		var roundFoldingRandomness []frontend.Variable
		roundFoldingRandomness, lastEval, err = merkle.RunWhirSumcheckRounds(api, lastEval, arthur, whirParams.FoldingFactorArray[r], 3)
		if err != nil {
			return
		}

		computedFold = computeFold(circuit.Leaves[r], roundFoldingRandomness, api)
		totalFoldingRandomness = append(totalFoldingRandomness, roundFoldingRandomness...)

		domainSize /= 2
		expDomainGenerator = api.Mul(expDomainGenerator, expDomainGenerator)
	}

	finalCoefficients, finalRandomnessPoints, err := merkle.GenerateFinalCoefficientsAndRandomnessPoints(api, arthur, whirParams, circuit, uapi, sc, domainSize, expDomainGenerator)
	if err != nil {
		return
	}

	finalEvaluations := polynomial.Univar(api, finalCoefficients, finalRandomnessPoints)

	for foldIndex := range computedFold {
		api.AssertIsEqual(computedFold[foldIndex], finalEvaluations[foldIndex])
	}

	finalSumcheckRandomness, lastEval, err := merkle.RunWhirSumcheckRounds(api, lastEval, arthur, whirParams.FinalSumcheckRounds, 3)
	if err != nil {
		return
	}

	totalFoldingRandomness = append(totalFoldingRandomness, finalSumcheckRandomness...)

	if whirParams.FinalFoldingPowBits > 0 {
		if err = merkle.RunPoW(api, sc, arthur, whirParams.FinalFoldingPowBits); err != nil {
			return
		}
	}

	totalFoldingRandomness = reverseVariables(totalFoldingRandomness)

	evaluationOfWPoly := computeWPoly(
		api,
		whirParams,
		initialSumcheckData,
		mainRoundData,
		totalFoldingRandomness,
		linearStatementValuesAtPoints,
		evaluationPoints,
	)

	api.AssertIsEqual(
		lastEval,
		api.Mul(evaluationOfWPoly, polynomial.Multivar(api, finalCoefficients, finalSumcheckRandomness)),
	)

	return totalFoldingRandomness, nil
}

//nolint:unused
// func runWhir(
// 	api frontend.API,
// 	arthur gnarkNimue.Arthur,
// 	uapi *uints.BinaryField[uints.U64],
// 	sc *skyscraper.Skyscraper,
// 	circuit Merkle,
// 	whirParams WHIRParams,
// 	linearStatementEvaluations []frontend.Variable,
// 	linearStatementValuesAtPoints []frontend.Variable,
// ) (totalFoldingRandomness []frontend.Variable, err error) {
// 	if err = fillInAndVerifyRootHash(0, api, uapi, sc, circuit, arthur); err != nil {
// 		return
// 	}

// 	initialOODQueries, initialOODAnswers, tempErr := fillInOODPointsAndAnswers(whirParams.CommittmentOODSamples, arthur)
// 	if tempErr != nil {
// 		err = tempErr
// 		return
// 	}

// 	initialCombinationRandomness, tempErr := GenerateCombinationRandomness(api, arthur, whirParams.CommittmentOODSamples+len(linearStatementEvaluations))
// 	if tempErr != nil {
// 		err = tempErr
// 		return
// 	}

// 	OODAnswersAndStatmentEvaluations := append(initialOODAnswers, linearStatementEvaluations...)
// 	lastEval := utilities.DotProduct(api, initialCombinationRandomness, OODAnswersAndStatmentEvaluations)

// 	initialSumcheckFoldingRandomness, lastEval, tempErr := runWhirSumcheckRounds(api, lastEval, arthur, whirParams.FoldingFactorArray[0], 3)
// 	if tempErr != nil {
// 		err = tempErr
// 		return
// 	}

// 	initialData := InitialSumcheckData{
// 		InitialOODQueries:            initialOODQueries,
// 		InitialCombinationRandomness: initialCombinationRandomness,
// 	}

// 	computedFold := computeFold(circuit.Leaves[0], initialSumcheckFoldingRandomness, api)

// 	mainRoundData := generateEmptyMainRoundData(whirParams)

// 	expDomainGenerator := utilities.Exponent(api, uapi, whirParams.StartingDomainBackingDomainGenerator, uints.NewU64(uint64(1<<whirParams.FoldingFactorArray[0])))
// 	domainSize := whirParams.DomainSize

// 	totalFoldingRandomness = initialSumcheckFoldingRandomness

// 	for r := range whirParams.ParamNRounds {
// 		if err = fillInAndVerifyRootHash(r+1, api, uapi, sc, circuit, arthur); err != nil {
// 			return
// 		}

// 		var roundOODAnswers []frontend.Variable
// 		mainRoundData.OODPoints[r], roundOODAnswers, err = fillInOODPointsAndAnswers(whirParams.RoundParametersOODSamples[r], arthur)
// 		if err != nil {
// 			return
// 		}

// 		if err = RunPoW(api, sc, arthur, whirParams.PowBits[r]); err != nil {
// 			return
// 		}

// 		mainRoundData.StirChallengesPoints[r], err = GenerateStirChallengePoints(api, arthur, whirParams.RoundParametersNumOfQueries[r], circuit.LeafIndexes[r], domainSize, uapi, expDomainGenerator, whirParams.FoldingFactorArray[r])
// 		if err != nil {
// 			return
// 		}

// 		mainRoundData.CombinationRandomness[r], err = GenerateCombinationRandomness(api, arthur, len(circuit.LeafIndexes[r])+whirParams.RoundParametersOODSamples[r])
// 		if err != nil {
// 			return
// 		}

// 		lastEval = api.Add(lastEval, calculateShiftValue(roundOODAnswers, mainRoundData.CombinationRandomness[r], computedFold, api))

// 		var roundFoldingRandomness []frontend.Variable
// 		roundFoldingRandomness, lastEval, err = runWhirSumcheckRounds(api, lastEval, arthur, whirParams.FoldingFactorArray[r], 3)
// 		if err != nil {
// 			return
// 		}

// 		computedFold = computeFold(circuit.Leaves[r+1], roundFoldingRandomness, api)
// 		totalFoldingRandomness = append(totalFoldingRandomness, roundFoldingRandomness...)

// 		domainSize /= 2
// 		expDomainGenerator = api.Mul(expDomainGenerator, expDomainGenerator)
// 	}

// 	finalCoefficients := make([]frontend.Variable, 1<<whirParams.FinalSumcheckRounds)
// 	if err = arthur.FillNextScalars(finalCoefficients); err != nil {
// 		return
// 	}

// 	if err = RunPoW(api, sc, arthur, whirParams.FinalPowBits); err != nil {
// 		return
// 	}

// 	finalRandomnessPoints, err := GenerateStirChallengePoints(api, arthur, whirParams.FinalQueries, circuit.LeafIndexes[whirParams.ParamNRounds], domainSize, uapi, expDomainGenerator, whirParams.FoldingFactorArray[whirParams.ParamNRounds])
// 	if err != nil {
// 		return
// 	}

// 	finalEvaluations := utilities.UnivarPoly(api, finalCoefficients, finalRandomnessPoints)

// 	for foldIndex := range computedFold {
// 		api.AssertIsEqual(computedFold[foldIndex], finalEvaluations[foldIndex])
// 	}

// 	finalSumcheckRandomness, lastEval, tempErr := runWhirSumcheckRounds(api, lastEval, arthur, whirParams.FinalSumcheckRounds, 3)
// 	if tempErr != nil {
// 		err = tempErr
// 		return
// 	}

// 	totalFoldingRandomness = append(totalFoldingRandomness, finalSumcheckRandomness...)

// 	totalFoldingRandomness = utilities.Reverse(totalFoldingRandomness)

// 	evaluationOfVPoly := computeWPoly(
// 		api,
// 		whirParams,
// 		initialData,
// 		mainRoundData,
// 		totalFoldingRandomness,
// 		linearStatementValuesAtPoints,
// 		evaluationPoints,
// 	)

// 	api.AssertIsEqual(
// 		lastEval,
// 		api.Mul(evaluationOfVPoly, utilities.MultivarPoly(finalCoefficients, finalSumcheckRandomness, api)),
// 	)

// 	err = nil
// 	return
// }
