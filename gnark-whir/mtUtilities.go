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

func ValidateFirstRound(api frontend.API, circuit Merkle, arthur gnark_nimue.Arthur, uapi *uints.BinaryField[uints.U64], sc *skyscraper.Skyscraper, batchSizeLen frontend.Variable, rootHashes []frontend.Variable, batchingRandomness frontend.Variable, stirChallengeIndexes []frontend.Variable, roundAnswers [][]frontend.Variable) error {

	for i := range circuit.Leaves {
		err := VerifyMerkleTreeProofs(api, uapi, sc, circuit.LeafIndexes[i], circuit.Leaves[i], circuit.LeafSiblingHashes[i], circuit.AuthPaths[i], rootHashes[i])
		if err != nil {
			return err
		}

		err = utilities.IsSubset(api, uapi, arthur, stirChallengeIndexes, circuit.LeafIndexes[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func parseBatchedCommitment(api frontend.API, arthur gnark_nimue.Arthur, whir_params WHIRParams) ([]frontend.Variable, frontend.Variable, []frontend.Variable, [][]frontend.Variable, error) {

	rootHashes := make([]frontend.Variable, whir_params.BatchSize)
	for i := range whir_params.BatchSize {
		rootHash := make([]frontend.Variable, 1)
		if err := arthur.FillNextScalars(rootHash); err != nil {
			return []frontend.Variable{}, 0, []frontend.Variable{}, [][]frontend.Variable{}, err
		}
		rootHashes[i] = rootHash[0]
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
		return []frontend.Variable{}, 0, []frontend.Variable{}, [][]frontend.Variable{}, err
	}
	return rootHashes, batchingRandomness[0], oodPoints, oodAnswers, nil
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
