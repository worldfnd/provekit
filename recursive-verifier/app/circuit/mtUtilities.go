package circuit

import (
	"fmt"
	"reilabs/whir-verifier-circuit/app/utilities"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

func initialSumcheck(
	api frontend.API,
	arthur gnarkNimue.Arthur,
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

func parseBatchedCommitment(arthur gnarkNimue.Arthur, whir_params WHIRParams) (frontend.Variable, frontend.Variable, []frontend.Variable, [][]frontend.Variable, error) {
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

func generateFinalCoefficientsAndRandomnessPoints(api frontend.API, arthur gnarkNimue.Arthur, whir_params WHIRParams, circuit Merkle, uapi *uints.BinaryField[uints.U64], sc *skyscraper.Skyscraper, domainSize int, expDomainGenerator frontend.Variable) ([]frontend.Variable, []frontend.Variable, error) {
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

// hashPublicInputs computes the hash of public inputs by treating them as field elements
// This mimics the Rust PublicInputs::hash() function using SHA-256, TODO : Shift to skyscraper hash function later
func hashPublicInputs(api frontend.API, sc *skyscraper.Skyscraper, publicInputs PublicInputs) (frontend.Variable, error) {
	if len(publicInputs.Values) == 0 {
		// Return zero if no public inputs
		return frontend.Variable(0), nil
	}

	// Use hint to compute SHA-256 hash outside the circuit
	// The hint function will be called during witness generation
	hashResult, err := api.Compiler().NewHint(utilities.HashPublicInputsHint, 1, publicInputs.Values...)
	if err != nil {
		return nil, fmt.Errorf("failed to create hash hint: %w", err)
	}

	return hashResult[0], nil
}

// verifyPublicInputsAndReadWeights reads and verifies the public inputs hash from the transcript,
// then reads the public weights challenge and query answer.
// Returns (publicWeightsChallenge, publicWeightsQueryAnswer, error)
func verifyPublicInputsAndReadWeights(
	api frontend.API,
	sc *skyscraper.Skyscraper,
	arthur gnarkNimue.Arthur,
	publicInputs PublicInputs,
) (frontend.Variable, []frontend.Variable, error) {
	// Read public inputs hash from transcript
	publicInputsHashBuf := make([]frontend.Variable, 1)
	if err := arthur.FillNextScalars(publicInputsHashBuf); err != nil {
		return nil, nil, fmt.Errorf("failed to read public inputs hash: %w", err)
	}

	// Compute expected public inputs hash
	expectedHash, err := hashPublicInputs(api, sc, publicInputs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute public inputs hash: %w", err)
	}

	// Verify hash matches
	api.AssertIsEqual(publicInputsHashBuf[0], expectedHash)

	// Read public weights vector random challenge
	publicWeightsChallenge := make([]frontend.Variable, 1)
	if err := arthur.FillChallengeScalars(publicWeightsChallenge); err != nil {
		return nil, nil, fmt.Errorf("failed to read public weights challenge: %w", err)
	}

	// Read WHIR public weights query answer (2 field elements: f_sum, g_sum)
	publicWeightsQueryAnswer := make([]frontend.Variable, 2)
	if err := arthur.FillNextScalars(publicWeightsQueryAnswer); err != nil {
		return nil, nil, fmt.Errorf("failed to read public weights query answer: %w", err)
	}

	return publicWeightsChallenge[0], publicWeightsQueryAnswer, nil
}

// readPublicWeightsQueryAnswer reads only the public weights query answer from the transcript.
// The challenge has already been read at the circuit level to match transcript order.
// Returns (publicWeightsQueryAnswer, error)
func readPublicWeightsQueryAnswer(arthur gnarkNimue.Arthur) ([]frontend.Variable, error) {
	// Read WHIR public weights query answer (2 field elements: f_sum, g_sum)
	publicWeightsQueryAnswer := make([]frontend.Variable, 2)
	if err := arthur.FillNextScalars(publicWeightsQueryAnswer); err != nil {
		return nil, fmt.Errorf("failed to read public weights query answer: %w", err)
	}

	return publicWeightsQueryAnswer, nil
}

// computePublicWeightsClaimedSum computes the claimed sum for the public weights constraint
// This is: public_f_sum + public_g_sum * batching_randomness
func computePublicWeightsClaimedSum(
	api frontend.API,
	publicWeightsQueryAnswer []frontend.Variable,
	batchingRandomness frontend.Variable,
) frontend.Variable {
	publicFSum := publicWeightsQueryAnswer[0]
	publicGSum := publicWeightsQueryAnswer[1]
	return api.Add(publicFSum, api.Mul(publicGSum, batchingRandomness))
}
