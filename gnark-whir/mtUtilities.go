package main

import (
	"reilabs/whir-verifier-circuit/utilities"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnark_nimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

type MerklePaths struct {
	Leaves            [][][]frontend.Variable
	LeafIndexes       [][]uints.U64
	LeafSiblingHashes [][][]uints.U8
	AuthPaths         [][][][]uints.U8
}

func initialSumcheck(
	api frontend.API,
	arthur gnark_nimue.Arthur,
	batchingRandomness frontend.Variable,
	initialOODQueries []frontend.Variable,
	initialOODAnswers []frontend.Variable,
	whirParams WHIRParams,
	linearStatementEvaluations [][]frontend.Variable,
) (InitialSumcheckData, frontend.Variable, []frontend.Variable, error) {

	initialCombinationRandomness, err := GenerateCombinationRandomness(api, arthur, len(initialOODAnswers)+len(linearStatementEvaluations[0]))
	if err != nil {
		return InitialSumcheckData{}, nil, nil, err
	}

	combinedLinearStatementEvaluations := make([]frontend.Variable, len(linearStatementEvaluations[0])) //[0, 1, 2]
	for evaluationIndex := range len(linearStatementEvaluations[0]) {
		sum := frontend.Variable(0)
		multiplier := frontend.Variable(1)
		for j := range len(linearStatementEvaluations) {
			sum = api.Add(sum, api.Mul(linearStatementEvaluations[j][evaluationIndex], multiplier))
			multiplier = api.Mul(multiplier, batchingRandomness)
		}
		combinedLinearStatementEvaluations[evaluationIndex] = sum
	}
	OODAnswersAndStatmentEvaluations := append(initialOODAnswers, combinedLinearStatementEvaluations...)
	lastEval := utilities.DotProduct(api, initialCombinationRandomness, OODAnswersAndStatmentEvaluations)

	initialSumcheckFoldingRandomness, lastEval, err := runWhirSumcheckRounds(api, lastEval, arthur, whirParams.FoldingFactorArray[0], 3)
	if err != nil {
		return InitialSumcheckData{}, nil, nil, err
	}

	return InitialSumcheckData{
		InitialOODQueries:            initialOODQueries,
		InitialCombinationRandomness: initialCombinationRandomness,
	}, lastEval, initialSumcheckFoldingRandomness, nil
}

func parseBatchedCommitment(arthur gnark_nimue.Arthur, whir_params WHIRParams) (frontend.Variable, frontend.Variable, []frontend.Variable, [][]frontend.Variable, error) {
	rootHash := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(rootHash); err != nil {
		return nil, nil, nil, [][]frontend.Variable{}, err
	}
	oodPoints := make([]frontend.Variable, 1)
	oodAnswers := make([][]frontend.Variable, whir_params.BatchSize)

	if err := arthur.FillChallengeScalars(oodPoints); err != nil {
		return nil, nil, nil, nil, err
	}
	for i := range whir_params.BatchSize {
		oodAnswer := make([]frontend.Variable, 1)

		if err := arthur.FillNextScalars(oodAnswer); err != nil {
			return nil, nil, nil, nil, err
		}
		oodAnswers[i] = oodAnswer
	}

	batchingRandomness := make([]frontend.Variable, 1)
	if err := arthur.FillChallengeScalars(batchingRandomness); err != nil {
		return nil, 0, nil, nil, err
	}
	return rootHash[0], batchingRandomness[0], oodPoints, oodAnswers, nil
}

func generateFinalCoefficientsAndRandomnessPoints(api frontend.API, arthur gnark_nimue.Arthur, whir_params WHIRParams, circuit Merkle, uapi *uints.BinaryField[uints.U64], sc *skyscraper.Skyscraper, domainSize int, expDomainGenerator frontend.Variable) ([]frontend.Variable, []frontend.Variable, error) {
	finalCoefficients := make([]frontend.Variable, 1<<whir_params.FinalSumcheckRounds)
	if err := arthur.FillNextScalars(finalCoefficients); err != nil {
		return nil, nil, err
	}

	if err := RunPoW(api, sc, arthur, whir_params.FinalPowBits); err != nil {
		return nil, nil, err
	}

	finalRandomnessPoints, err := GenerateStirChallengePoints(api, arthur, whir_params.FinalQueries, circuit.LeafIndexes[len(circuit.LeafIndexes)-1], domainSize, uapi, expDomainGenerator, whir_params.FoldingFactorArray[len(whir_params.FoldingFactorArray)-1])
	if err != nil {
		return nil, nil, err
	}

	return finalCoefficients, finalRandomnessPoints, nil
}

// rlcBatchedLeaves collapses a wide leaf (length foldSize * batchSize) into foldSize via
// out[j] = sum_{b=0..batchSize-1} B^b * leaf[b*foldSize + j]
func rlcBatchedLeaves(api frontend.API, leaves [][]frontend.Variable, foldSize int, batchSize int, B frontend.Variable) [][]frontend.Variable {
	collapsed := make([][]frontend.Variable, len(leaves))
	for i := range leaves {
		collapsed[i] = make([]frontend.Variable, foldSize)
		for j := 0; j < foldSize; j++ {
			sum := frontend.Variable(0)
			pow := frontend.Variable(1)
			for b := 0; b < batchSize; b++ {
				idx := b*foldSize + j
				sum = api.Add(sum, api.Mul(pow, leaves[i][idx]))
				pow = api.Mul(pow, B)
			}
			collapsed[i][j] = sum
		}
	}
	return collapsed
}

func combineFirstRoundLeaves(api frontend.API, firstRoundPath [][][]frontend.Variable, combinationRandomness frontend.Variable) [][]frontend.Variable {
	combinedFirstRound := firstRoundPath[0]

	multiplier := combinationRandomness
	for i := 1; i < len(firstRoundPath); i++ {
		for j := range firstRoundPath[i] {
			for k := range firstRoundPath[i][j] {
				combinedFirstRound[j][k] = api.Add(combinedFirstRound[j][k], api.Mul(multiplier, firstRoundPath[i][j][k]))
			}
		}
		multiplier = api.Mul(multiplier, combinationRandomness)
	}
	return combinedFirstRound
}
