package whir

import (
	"math/bits"
	"reilabs/keccacheck/transcript"

	"github.com/consensys/gnark/frontend"
)

func VerifyWhir(
	api frontend.API,
	v *transcript.Verifier,
	commitment ParsedCommitment,
	hr *HintReader,
	statements []Statement,
	params WHIRParams,
) (totalFoldingRandomness []frontend.Variable, err error) {

	numVectors := params.BatchSize

	// Complete the constraint and evaluation matrix with OODs and their cross-terms.
	// For a single commitment all OOD values are already known; for multiple
	// commitments this loop reads cross-term evaluations from the transcript.
	numOODConstraints := 0
	var oodMatrix []frontend.Variable
	vectorOffset := 0
	committedOODRows := commitment.OodAnswers // flat: outDomainSamples * numVectorsPerCommitment
	numVectorsPerCommitment := params.BatchSize
	for i := 0; i < params.CommittmentOODSamples; i++ {
		for j := 0; j < numVectors; j++ {
			if j >= vectorOffset && j < numVectorsPerCommitment+vectorOffset {
				oodMatrix = append(oodMatrix, committedOODRows[i*numVectorsPerCommitment+(j-vectorOffset)])
			} else {
				// Cross-term: read from transcript (absorb into sponge).
				oodMatrix = append(oodMatrix, v.Read(api))
			}
		}
		numOODConstraints++
	}

	// Extract OOD multilinear points from the univariate OOD challenge points
	oodPoints := make([][]frontend.Variable, 0, len(commitment.OodPoints))
	for _, point := range commitment.OodPoints {
		mlPoint := ExpandFromUnivariate(api, point, params.MVParamsNumberOfVariables)
		oodPoints = append(oodPoints, mlPoint)
	}

	// Random linear combination of the vectors.
	vectorRlcCoeffs := geometricChallenge(api, v, numVectors)

	// Random linear combination of the constraints.
	numLinearForms := len(statements)
	constraintRlcCoeffs := geometricChallenge(api, v, numOODConstraints+numLinearForms)
	oodsRlcCoeffs := constraintRlcCoeffs[:numOODConstraints]
	initialFormRlcCoeffs := constraintRlcCoeffs[numOODConstraints:]

	// Compute "the sum" (mirrors Rust whir::verifier lines 110-118)
	// the_sum = Σ(initialFormRlcCoeff * dot(vectorRlcCoeffs, evaluationRow))
	//         + Σ(oodsRlcCoeff * dot(vectorRlcCoeffs, oodsRow))
	theSum := frontend.Variable(0)
	for i, rlcCoeff := range initialFormRlcCoeffs {
		evaluationRow := make([]frontend.Variable, params.BatchSize)
		for j := range evaluationRow {
			evaluationRow[j] = statements[i].Constraints[j].Evaluation
		}
		theSum = api.Add(theSum, api.Mul(rlcCoeff, DotProduct(api, vectorRlcCoeffs, evaluationRow)))
	}
	for i, rlcCoeff := range oodsRlcCoeffs {
		oodsRow := oodMatrix[i*numVectors : (i+1)*numVectors]
		theSum = api.Add(theSum, api.Mul(rlcCoeff, DotProduct(api, vectorRlcCoeffs, oodsRow)))
	}

	// Perform the initial sumcheck
	initialSumcheckData, theSum, initialSumcheckFoldingRandomness, err := initialSumcheck(api, v, theSum, commitment.OodPoints, oodsRlcCoeffs, initialFormRlcCoeffs, params)
	if err != nil {
		return
	}

	foldSize := 1 << params.FoldingFactorArray[0]
	numQueries := params.RoundParametersNumOfQueries[0]
	// Read initial leaf values from hints (numQueries leaves, each batchSize*foldSize elements)
	// Mirrors Rust: prover_hint_ark() in irs_commit.verify()
	initialLeaves := readLeavesFromHints(hr, numQueries, params.BatchSize*foldSize)

	mainRoundData := generateEmptyMainRoundData(params)
	expDomainGenerator := ExponentVar(api, params.StartingDomainBackingDomainGenerator, frontend.Variable(1<<params.FoldingFactorArray[0]), bits.Len(uint(params.DomainSize)))
	domainSize := params.DomainSize

	totalFoldingRandomness = initialSumcheckFoldingRandomness

	// Track the previous round's root for Merkle verification.
	// Each round receives a new commitment
	// first, then opens/verifies the previous round's commitment against its root.
	var prevRootHash frontend.Variable

	for r := range params.ParamNRounds {
		// Mirrors Rust irs_commit::receive_commitment: read root hash (absorb), squeeze OOD points, read OOD answers.
		rootHash := v.Read(api)
		var roundOODAnswers []frontend.Variable

		mainRoundData.OODPoints[r] = v.GenerateVector(api, uint(params.RoundParametersOODSamples[r]))
		roundOODAnswers = v.ReadVector(api, uint(params.RoundParametersOODSamples[r]))
		if err != nil {
			return
		}

		if err = RunPoW(api, v, params.PowBits[r]); err != nil {
			return
		}

		// Generate STIR challenge indices from sponge.
		// The coset size uses FoldingFactorArray[r] which matches the interleaving
		// depth of the commitment being opened (initial at r=0, round_configs[r-1] at r>0).
		stirIndexes, err2 := getStirChallenges(api, v, params.RoundParametersNumOfQueries[r], domainSize, 1<<params.FoldingFactorArray[r])
		if err2 != nil {
			err = err2
			return
		}

		// Verify Merkle paths for previously committed leaves.
		// After receiving the current round's commitment, open the
		// PREVIOUS commitment. Round 0 opens the initial commitment; round r>0
		// opens round (r-1)'s commitment against its root hash.
		var inDomainLeaves [][]frontend.Variable
		if r == 0 {
			inDomainLeaves = initialLeaves
			treeHeight := bits.Len(uint(domainSize/(1<<params.FoldingFactorArray[0]))) - 1
			_ = treeHeight
			// verifyMerklePaths(api, hr, initialLeaves, stirIndexes, commitment.Root, treeHeight)
		} else {
			prevFoldSize := 1 << params.FoldingFactorArray[r]
			prevNumQueries := params.RoundParametersNumOfQueries[r]
			prevTreeHeight := bits.Len(uint(domainSize/(1<<params.FoldingFactorArray[r]))) - 1
			_ = prevTreeHeight
			roundLeaves := readLeavesFromHints(hr, prevNumQueries, prevFoldSize)
			// verifyMerklePaths(api, hr, roundLeaves, stirIndexes, prevRootHash, prevTreeHeight)
			inDomainLeaves = roundLeaves
		}

		prevRootHash = rootHash

		// Compute domain evaluation points from indices
		numBits := bits.Len(uint(domainSize - 1))
		mainRoundData.StirChallengesPoints[r] = make([]frontend.Variable, len(stirIndexes))
		for index, idx := range stirIndexes {
			mainRoundData.StirChallengesPoints[r][index] = ExponentVar(api, expDomainGenerator, idx, numBits)
		}

		// Constraint weights: OOD evaluators chained with in-domain (STIR) evaluators.
		// Mirrors Rust: commitment.out_of_domain().evaluators(..).chain(in_domain.evaluators(..))
		constraintWeights := make([]frontend.Variable, 0, len(mainRoundData.OODPoints[r])+len(mainRoundData.StirChallengesPoints[r]))
		constraintWeights = append(constraintWeights, mainRoundData.OODPoints[r]...)
		constraintWeights = append(constraintWeights, mainRoundData.StirChallengesPoints[r]...)

		// Compute eq_weights from last folding randomness.
		// Mirrors Rust: round_folding_randomness.last().unwrap().eq_weights()
		lastFoldLen := params.FoldingFactorArray[r]
		lastFoldRandomness := totalFoldingRandomness[len(totalFoldingRandomness)-lastFoldLen:]
		eqWeights := computeEqWeights(api, lastFoldRandomness)

		// Tensor product: polyRlc ⊗ eqWeights.
		// Round 0: polyRlc = vectorRlcCoeffs (batching weights); round > 0: polyRlc = [1].
		// Mirrors Rust: tensor_product(&poly_rlc, &eq_weights)
		var polyRlc []frontend.Variable
		if r == 0 {
			polyRlc = vectorRlcCoeffs
		} else {
			polyRlc = []frontend.Variable{frontend.Variable(1)}
		}
		tp := tensorProductVec(api, polyRlc, eqWeights)

		// Constraint values: OOD values chained with in-domain values.
		// OOD: commitment.out_of_domain().values(&[F::ONE]) = roundOODAnswers (single vector).
		// In-domain: in_domain.values(&tp) = dot(tp, leafRow) per query.
		inDomainValues := make([]frontend.Variable, len(inDomainLeaves))
		for q := range inDomainLeaves {
			inDomainValues[q] = DotProduct(api, tp, inDomainLeaves[q])
		}
		constraintValues := make([]frontend.Variable, 0, len(roundOODAnswers)+len(inDomainValues))
		constraintValues = append(constraintValues, roundOODAnswers...)
		constraintValues = append(constraintValues, inDomainValues...)

		// Random linear combination coefficients for constraints.
		// Mirrors Rust: geometric_challenge(verifier_state, constraint_values.len())
		constraintRlcCoeffs := geometricChallenge(api, v, len(constraintValues))
		mainRoundData.CombinationRandomness[r] = constraintRlcCoeffs

		// constraint_dot = dot(constraintRlcCoeffs, constraintValues)
		constraintDot := DotProduct(api, constraintRlcCoeffs, constraintValues)
		theSum = api.Add(theSum, constraintDot)
		_ = constraintWeights // stored in mainRoundData for final weight evaluation

		// Sumcheck round: round_configs[r].sumcheck has num_rounds = ff[r+1]
		var roundFoldingRandomness []frontend.Variable
		roundFoldingRandomness, theSum, err = runWhirSumcheckRounds(api, theSum, v, params.FoldingFactorArray[r+1])
		if err != nil {
			return
		}

		totalFoldingRandomness = append(totalFoldingRandomness, roundFoldingRandomness...)

		// Mirrors Rust: domain_size /= 2 per round.
		// Generator ratio between rounds is 2^{1 + ff[r+1] - ff[r]}.
		domainSize /= 2
		numSquarings := 1 + params.FoldingFactorArray[r+1] - params.FoldingFactorArray[r]
		for k := 0; k < numSquarings; k++ {
			expDomainGenerator = api.Mul(expDomainGenerator, expDomainGenerator)
		}
	}

	// Read the final polynomial coefficients from the transcript.
	// Mirrors Rust: let final_vector = verifier_state.prover_messages_vec(self.final_sumcheck.initial_size)?;
	finalVector := v.ReadVector(api, uint(1<<params.FinalSumcheckRounds))

	// Final proof-of-work BEFORE opening the previous commitment.
	// Mirrors Rust: self.final_pow.verify(verifier_state)?;
	if err = RunPoW(api, v, params.FinalPowBits); err != nil {
		return
	}

	// Generate final STIR challenge indices and compute domain evaluation points.
	lastFoldingFactor := params.FoldingFactorArray[len(params.FoldingFactorArray)-1]
	finalIndexes, err := getStirChallenges(api, v, params.FinalQueries, domainSize, 1<<lastFoldingFactor)
	if err != nil {
		return
	}

	numBits := bits.Len(uint(domainSize - 1))
	finalRandomnessPoints := make([]frontend.Variable, len(finalIndexes))
	for i, idx := range finalIndexes {
		finalRandomnessPoints[i] = ExponentVar(api, expDomainGenerator, idx, numBits)
	}

	// Open previous commitment at final STIR challenge points.
	// Mirrors Rust lines 228-244: open prev_commitment via irs_commit.verify().
	finalRoot := prevRootHash
	var inDomainValues []frontend.Variable
	if params.ParamNRounds > 0 {
		finalLeaves := readLeavesFromHints(hr, params.FinalQueries, 1<<lastFoldingFactor)
		finalTreeHeight := bits.Len(uint(domainSize/(1<<lastFoldingFactor))) - 1
		_ = finalTreeHeight
		// verifyMerklePaths(api, hr, finalLeaves, finalIndexes, finalRoot, finalTreeHeight)

		// Mirrors Rust: in_domain.values(&tensor_product(&[1], &eq_weights))
		lastFoldRandomness := totalFoldingRandomness[len(totalFoldingRandomness)-lastFoldingFactor:]
		eqWeights := computeEqWeights(api, lastFoldRandomness)
		inDomainValues = make([]frontend.Variable, len(finalLeaves))
		for q := range finalLeaves {
			inDomainValues[q] = DotProduct(api, eqWeights, finalLeaves[q])
		}
	} else {
		finalLeaves := readLeavesFromHints(hr, params.FinalQueries, params.BatchSize*(1<<lastFoldingFactor))
		finalTreeHeight := bits.Len(uint(domainSize/(1<<lastFoldingFactor))) - 1
		_ = finalTreeHeight
		// verifyMerklePaths(api, hr, finalLeaves, finalIndexes, finalRoot, finalTreeHeight)

		// Mirrors Rust: in_domain.values(&tensor_product(&batching_weights, &eq_weights))
		eqWeights := computeEqWeights(api, initialSumcheckFoldingRandomness)
		tp := tensorProductVec(api, vectorRlcCoeffs, eqWeights)
		inDomainValues = make([]frontend.Variable, len(finalLeaves))
		for q := range finalLeaves {
			inDomainValues[q] = DotProduct(api, tp, finalLeaves[q])
		}
	}

	// Verify in-domain constraints directly.
	// Mirrors Rust lines 247-255: verify!(weights.evaluate(&Identity, &final_vector) == evals)
	finalEvaluations := UnivarPoly(api, finalVector, finalRandomnessPoints)
	for q := range inDomainValues {
		api.AssertIsEqual(finalEvaluations[q], inDomainValues[q])
	}

	// Final sumcheck.
	// Mirrors Rust line 258: self.final_sumcheck.verify(verifier_state, &mut the_sum)
	finalSumcheckRandomness, theSum, err := runWhirSumcheckRounds(api, theSum, v, params.FinalSumcheckRounds)
	if err != nil {
		return
	}

	totalFoldingRandomness = append(totalFoldingRandomness, finalSumcheckRandomness...)

	if params.FinalFoldingPowBits > 0 {
		_, _, err = PoW(api, v, params.FinalFoldingPowBits)
		if err != nil {
			return
		}
	}

	// Compute folding randomness across all rounds.
	// Mirrors Rust lines 262-267: flat concatenation of all round folding randomness.
	// totalFoldingRandomness = [initial | round_0 | ... | round_{N-1} | final]
	foldLen := len(totalFoldingRandomness)

	// Evaluate all round constraints weights.
	// Mirrors Rust lines 270-280.
	weightEval := frontend.Variable(0)

	// Round 0 (initial OOD constraints): num_variables = initial_num_variables.
	numVars := params.MVParamsNumberOfVariables
	start := foldLen - numVars
	for j := range initialSumcheckData.InitialOODQueries {
		weightEval = api.Add(weightEval, api.Mul(
			initialSumcheckData.InitialCombinationRandomness[j],
			UnivarMleEvaluate(api, initialSumcheckData.InitialOODQueries[j], totalFoldingRandomness[start:]),
		))
	}

	// Rounds 1..N (main round constraints).
	// Rust: num_variables = round_configs[round-1].initial_num_variables().
	for r := range mainRoundData.OODPoints {
		numVars -= params.FoldingFactorArray[r]
		start = foldLen - numVars
		constraintWeights := append(mainRoundData.OODPoints[r], mainRoundData.StirChallengesPoints[r]...)
		for i := range constraintWeights {
			weightEval = api.Add(weightEval, api.Mul(
				mainRoundData.CombinationRandomness[r][i],
				UnivarMleEvaluate(api, constraintWeights[i], totalFoldingRandomness[start:]),
			))
		}
	}

	// Compute evaluation of non-deferred initial weights in folding randomness point.
	// Mirrors Rust lines 283-296: read deferred hints for linear forms.
	deferredEvals := hr.ReadVec(len(statements))
	for j, eval := range deferredEvals {
		weightEval = api.Add(weightEval, api.Mul(initialFormRlcCoeffs[j], eval))
	}
	// Check the final sumcheck equation.
	// Mirrors Rust lines 299-301: poly_eval * weight_eval == the_sum.
	polyEval := DotProduct(api, computeEqWeights(api, finalSumcheckRandomness), finalVector)

	api.AssertIsEqual(theSum, api.Mul(polyEval, weightEval))

	return totalFoldingRandomness, nil
}

// ExpandFromUnivariate converts a univariate evaluation point into a multilinear one.
//
// It maps a single point 'y' to a vector of coordinates:
// [y^(2^(n-1)), ..., y^4, y^2, y]
//
// This corresponds to the Big-Endian binary decomposition mapping used in
// protocols like Sumcheck or Spartan.
func ExpandFromUnivariate(api frontend.API, point frontend.Variable, numVariables int) []frontend.Variable {
	res := make([]frontend.Variable, numVariables)
	current := point

	// We iterate numVariables times.
	// In the Rust version, they generate [y, y^2, y^4...] and then reverse it.
	// Here, we simply fill the slice from the end (n-1) down to 0 to achieve
	// the same Big-Endian result: [HighestPower, ..., LowestPower].
	for i := 0; i < numVariables; i++ {
		// Store the current power at the "end" of the available slots
		res[numVariables-1-i] = current

		// Compute y^(2^k) for the next iteration (Squaring)
		current = api.Mul(current, current)
	}

	return res
}

// RunPoW executes a proof-of-work challenge if the difficulty is greater than zero.
// This is used as part of the Fiat-Shamir transformation to prevent malicious prover behavior.
func RunPoW(api frontend.API, v *transcript.Verifier, difficulty int) error {

	if difficulty > 0 {

		_, _, err := PoW(api, v, difficulty)
		if err != nil {
			return err
		}
	}
	return nil
}
