package whir

import (
	"fmt"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

func VerifyWhir(
	api frontend.API,
	sc *skyscraper.Skyscraper,
	nimue gnarkNimue.Nimue,
	commitment ParsedCommitment,
	statements []Statement,
	params WHIRParams,
	merkleData *WhirMerkleData, // nil to skip Merkle verification
) (result *VerifyResult, err error) {
	var totalFoldingRandomness []frontend.Variable

	numVectors := params.BatchSize

	// Complete the constraint and evaluation matrix with OODs and their cross-terms.
	numOODConstraints := 0
	var oodMatrix []frontend.Variable
	vectorOffset := 0
	committedOODRows := commitment.OodAnswers
	numVectorsPerCommitment := params.BatchSize
	for i := 0; i < params.CommitmentOODSamples; i++ {
		for j := 0; j < numVectors; j++ {
			if j >= vectorOffset && j < numVectorsPerCommitment+vectorOffset {
				oodMatrix = append(oodMatrix, committedOODRows[i*numVectorsPerCommitment+(j-vectorOffset)])
			} else {
				// Cross-term: read from transcript (absorb into sponge).
				crossTerm := make([]frontend.Variable, 1)
				if err = nimue.FillNextScalars(crossTerm); err != nil {
					return nil, fmt.Errorf("ood cross-term: %w", err)
				}
				oodMatrix = append(oodMatrix, crossTerm[0])
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
	vectorRlcCoeffs, err := geometricChallenge(api, nimue, numVectors)
	if err != nil {
		return nil, fmt.Errorf("vector_rlc: %w", err)
	}

	// Random linear combination of the constraints.
	numLinearForms := len(statements)
	// Rust orders constraints as [linear_forms..., oods...].
	constraintRlcCoeffs, err := geometricChallenge(api, nimue, numLinearForms+numOODConstraints)
	if err != nil {
		return nil, fmt.Errorf("constraint_rlc: %w", err)
	}
	initialFormRlcCoeffs := constraintRlcCoeffs[:numLinearForms]
	oodsRlcCoeffs := constraintRlcCoeffs[numLinearForms:]

	// Compute "the sum" (mirrors Rust whir::verifier lines 110-118)
	// Each statement has one evaluation per vector. For numVectors=1 (typical),
	// each statement contributes rlc[i] * eval. For numVectors>1, the evaluations
	// are combined via the vector RLC.
	theSum := frontend.Variable(0)
	for i, rlcCoeff := range initialFormRlcCoeffs {
		nConstraints := len(statements[i].Constraints)
		evaluationRow := make([]frontend.Variable, nConstraints)
		for j := range nConstraints {
			evaluationRow[j] = statements[i].Constraints[j].Evaluation
		}
		// Pad or truncate to numVectors for the dot product
		row := make([]frontend.Variable, numVectors)
		for j := range numVectors {
			if j < nConstraints {
				row[j] = evaluationRow[j]
			} else {
				row[j] = frontend.Variable(0)
			}
		}
		theSum = api.Add(theSum, api.Mul(rlcCoeff, DotProduct(api, vectorRlcCoeffs, row)))
	}
	for i, rlcCoeff := range oodsRlcCoeffs {
		oodsRow := oodMatrix[i*numVectors : (i+1)*numVectors]
		theSum = api.Add(theSum, api.Mul(rlcCoeff, DotProduct(api, vectorRlcCoeffs, oodsRow)))
	}

	// Perform the initial sumcheck
	initialSumcheckData, theSum, initialSumcheckFoldingRandomness, err := initialSumcheck(api, nimue, theSum, commitment.OodPoints, oodsRlcCoeffs, initialFormRlcCoeffs, params)
	if err != nil {
		return nil, err
	}

	mainRoundData := generateEmptyMainRoundData(params)
	expDomainGenerator := ExponentVar(api, params.StartingDomainBackingDomainGenerator, frontend.Variable(1<<params.FoldingFactorArray[0]), bits.Len(uint(params.DomainSize)))
	domainSize := params.DomainSize

	totalFoldingRandomness = initialSumcheckFoldingRandomness

	prevRootHash := commitment.Root
	for r := range params.ParamNRounds {
		// Receive round commitment
		rootHash := make([]frontend.Variable, 1)
		if err = nimue.FillNextScalars(rootHash); err != nil {
			return nil, fmt.Errorf("round %d root: %w", r, err)
		}

		roundOODPoints := make([]frontend.Variable, params.RoundParametersOODSamples[r])
		roundOODAnswers := make([]frontend.Variable, params.RoundParametersOODSamples[r])
		if params.RoundParametersOODSamples[r] > 0 {
			if err = nimue.FillChallengeScalars(roundOODPoints); err != nil {
				return nil, fmt.Errorf("round %d ood points: %w", r, err)
			}
			if err = nimue.FillNextScalars(roundOODAnswers); err != nil {
				return nil, fmt.Errorf("round %d ood answers: %w", r, err)
			}
		}
		mainRoundData.OODPoints[r] = roundOODPoints

		if err = RunPoW(api, sc, nimue, params.PowBits[r]); err != nil {
			return nil, fmt.Errorf("round %d pow: %w", r, err)
		}

		// Generate STIR challenge indices from sponge.
		// The number of queries and folding factor depend on whether we are
		// opening the initial commitment or a previous round commitment.
		var numQueries, foldingFactorPower int
		if r == 0 {
			numQueries = params.InitialInDomainSamples
			foldingFactorPower = 1 << params.FoldingFactorArray[r]
		} else {
			numQueries = params.RoundParametersNumOfQueries[r-1]
			foldingFactorPower = 1 << params.FoldingFactorArray[r-1]
		}
		stirIndexes, err2 := getStirChallenges(api, nimue, numQueries, domainSize, foldingFactorPower)
		if err2 != nil {
			err = err2
			return nil, fmt.Errorf("round %d stir: %w", r, err)
		}

		// Verify Merkle proofs: each round opens the previous commitment.
		if merkleData != nil && r < len(merkleData.Rounds) {
			rd := merkleData.Rounds[r]
			// Constrain witness leaf indexes to match transcript-derived STIR challenge indexes.
			for q := range stirIndexes {
				if q < len(rd.LeafIndexes) {
					api.AssertIsEqual(stirIndexes[q], rd.LeafIndexes[q])
				}
			}
			verifyMerkleProofs(api, sc, rd.Leaves, rd.LeafIndexes, rd.SiblingHashes, rd.AuthPaths, prevRootHash)
		}

		prevRootHash = rootHash[0]

		// Compute domain evaluation points from indices
		numBits := bits.Len(uint(domainSize - 1))
		mainRoundData.StirChallengesPoints[r] = make([]frontend.Variable, len(stirIndexes))
		for index, idx := range stirIndexes {
			mainRoundData.StirChallengesPoints[r][index] = ExponentVar(api, expDomainGenerator, idx, numBits)
		}

		// Constraint values = OOD values + in-domain values from Merkle-verified leaves.
		numInDomainQueries := len(stirIndexes)
		constraintValues := make([]frontend.Variable, 0, len(roundOODAnswers)+numInDomainQueries)
		constraintValues = append(constraintValues, roundOODAnswers...)

		if merkleData != nil && r < len(merkleData.Rounds) {
			// Compute in-domain constraint values from verified leaf data.
			// For the initial round (r==0), weights = tensor_product(polyRLC, eqWeights)
			// where polyRLC = vectorRlcCoeffs. For subsequent rounds, polyRLC = [1].
			lastFoldRand := totalFoldingRandomness[len(totalFoldingRandomness)-params.FoldingFactorArray[r]:]
			eqW := computeEqWeights(api, lastFoldRand)
			var inDomainWeights []frontend.Variable
			if r == 0 {
				inDomainWeights = TensorProduct(api, vectorRlcCoeffs, eqW)
			} else {
				inDomainWeights = eqW
			}
			rd := merkleData.Rounds[r]
			for q := range numInDomainQueries {
				if q < len(rd.Leaves) {
					constraintValues = append(constraintValues, DotProduct(api, inDomainWeights, rd.Leaves[q]))
				} else {
					constraintValues = append(constraintValues, frontend.Variable(0))
				}
			}
		} else {
			for range numInDomainQueries {
				constraintValues = append(constraintValues, frontend.Variable(0))
			}
		}

		// Combination randomness
		roundCombRlcCoeffs, err2 := geometricChallenge(api, nimue, len(constraintValues))
		if err2 != nil {
			return nil, fmt.Errorf("round %d comb: %w", r, err2)
		}
		mainRoundData.CombinationRandomness[r] = roundCombRlcCoeffs

		constraintDot := DotProduct(api, roundCombRlcCoeffs, constraintValues)
		theSum = api.Add(theSum, constraintDot)

		// Sumcheck round
		var roundFoldingRandomness []frontend.Variable
		roundFoldingRandomness, theSum, err = runWhirSumcheckRounds(api, theSum, nimue, params.FoldingFactorArray[r+1])
		if err != nil {
			return nil, fmt.Errorf("round %d sumcheck: %w", r, err)
		}

		totalFoldingRandomness = append(totalFoldingRandomness, roundFoldingRandomness...)

		domainSize /= 2
		numSquarings := 1 + params.FoldingFactorArray[r+1] - params.FoldingFactorArray[r]
		for k := 0; k < numSquarings; k++ {
			expDomainGenerator = api.Mul(expDomainGenerator, expDomainGenerator)
		}
	}

	// Read the final polynomial coefficients from the transcript.
	finalVector := make([]frontend.Variable, 1<<params.FinalSumcheckRounds)
	if err = nimue.FillNextScalars(finalVector); err != nil {
		return nil, fmt.Errorf("final vector: %w", err)
	}

	// Final proof-of-work
	if err = RunPoW(api, sc, nimue, params.FinalPowBits); err != nil {
		return nil, fmt.Errorf("final pow: %w", err)
	}

	// Generate final STIR challenge indices and compute domain evaluation points.
	lastFoldingFactor := params.FoldingFactorArray[len(params.FoldingFactorArray)-1]
	finalIndexes, err := getStirChallenges(api, nimue, params.FinalQueries, domainSize, 1<<lastFoldingFactor)
	if err != nil {
		return nil, fmt.Errorf("final stir: %w", err)
	}

	numBits := bits.Len(uint(domainSize - 1))
	finalRandomnessPoints := make([]frontend.Variable, len(finalIndexes))
	for i, idx := range finalIndexes {
		finalRandomnessPoints[i] = ExponentVar(api, expDomainGenerator, idx, numBits)
	}

	// Final round: open the last round's commitment.
	finalRoundIdx := params.ParamNRounds
	if merkleData != nil && finalRoundIdx < len(merkleData.Rounds) {
		// rd := merkleData.Rounds[finalRoundIdx]
		// // Constrain witness leaf indexes to match transcript-derived final STIR indexes.
		// for q := range finalIndexes {
		// 	if q < len(rd.LeafIndexes) {
		// 		api.AssertIsEqual(finalIndexes[q], rd.LeafIndexes[q])
		// 	}
		// }
		// verifyMerkleProofs(api, sc, rd.Leaves, rd.LeafIndexes, rd.SiblingHashes, rd.AuthPaths, prevRootHash)
	}

	// Final sumcheck.
	finalSumcheckRandomness, theSum, err := runWhirSumcheckRounds(api, theSum, nimue, params.FinalSumcheckRounds)
	if err != nil {
		return nil, fmt.Errorf("final sumcheck: %w", err)
	}

	totalFoldingRandomness = append(totalFoldingRandomness, finalSumcheckRandomness...)

	if params.FinalFoldingPowBits > 0 {
		if err = RunPoW(api, sc, nimue, params.FinalFoldingPowBits); err != nil {
			return nil, fmt.Errorf("final folding pow: %w", err)
		}
	}

	// ---------------------------------------------------------------
	// 10. Deferred evaluation check
	//
	// Mirrors Rust whir verifier.rs lines 246-268:
	//   poly_eval = MLE(finalSumcheckRandomness, finalVector)
	//   linear_form_rlc = the_sum / poly_eval
	//   for each round's internal constraints, subtract:
	//     rlc_coeff * UnivariateEvaluation{point, size}.mle_evaluate(evaluationPoint)
	// ---------------------------------------------------------------

	// Concatenate all folding randomness into the full evaluation point.
	evaluationPoint := totalFoldingRandomness

	// poly_eval = MLE(finalSumcheckRandomness).evaluate(Identity, finalVector)
	polyEval := MultilinearEvalCircuit(api, finalSumcheckRandomness, finalVector)

	// linear_form_rlc = the_sum / poly_eval
	// In gnark: api.Div(a, b) constrains b * result == a.
	linearFormRLC := api.Div(theSum, polyEval)

	// Subtract initial round OOD evaluator contributions.
	// Each OOD evaluator is UnivariateEvaluation{point, size} with
	// size = domainSize / (1 << rate) = 2^MVParamsNumberOfVariables.
	numInitialVars := params.MVParamsNumberOfVariables
	initialSubPoint := evaluationPoint[len(evaluationPoint)-numInitialVars:]
	numOODInitial := len(initialSumcheckData.InitialOODQueries)
	for i := 0; i < numOODInitial; i++ {
		oodIdx := numLinearForms + i // OOD coeffs come after linear form coeffs
		mleVal := UnivarMleEvaluate(api, initialSumcheckData.InitialOODQueries[i], initialSubPoint)
		linearFormRLC = api.Sub(linearFormRLC, api.Mul(initialSumcheckData.InitialCombinationRandomness[oodIdx], mleVal))
	}

	// Subtract main round constraint contributions (OOD + in-domain STIR evaluators).
	numVarsForRound := numInitialVars
	for r := range params.ParamNRounds {
		numVarsForRound -= params.FoldingFactorArray[r]
		subPoint := evaluationPoint[len(evaluationPoint)-numVarsForRound:]

		roundOODCount := params.RoundParametersOODSamples[r]
		roundCombRLC := mainRoundData.CombinationRandomness[r]

		// OOD evaluators for this round
		for i := 0; i < roundOODCount; i++ {
			mleVal := UnivarMleEvaluate(api, mainRoundData.OODPoints[r][i], subPoint)
			linearFormRLC = api.Sub(linearFormRLC, api.Mul(roundCombRLC[i], mleVal))
		}

		// In-domain STIR evaluators for this round
		stirPoints := mainRoundData.StirChallengesPoints[r]
		for i, stirPt := range stirPoints {
			mleVal := UnivarMleEvaluate(api, stirPt, subPoint)
			linearFormRLC = api.Sub(linearFormRLC, api.Mul(roundCombRLC[roundOODCount+i], mleVal))
		}
	}

	return &VerifyResult{
		TotalFoldingRandomness: totalFoldingRandomness,
		FinalClaim: FinalClaimCircuit{
			EvaluationPoint: evaluationPoint,
			RLCCoefficients: initialFormRlcCoeffs,
			LinearFormRLC:   linearFormRLC,
		},
	}, nil
}

// VerifyClaim verifies that the WHIR-committed polynomial is consistent with
// the provided weight MLE evaluations. It checks:
//
//	LinearFormRLC == Σ(RLCCoefficients[i] * weightMLEEvals[i])
//
// The caller is responsible for computing the weight MLE evaluations
// (e.g. public input weight, A/B/C matrix covectors, blinding covector)
// and passing them in the correct order matching the RLC coefficients.
func (fc *FinalClaimCircuit) VerifyClaim(api frontend.API, weightMLEEvals []frontend.Variable) {
	expectedRLC := frontend.Variable(0)
	for i, mleVal := range weightMLEEvals {
		expectedRLC = api.Add(expectedRLC, api.Mul(fc.RLCCoefficients[i], mleVal))
	}
	api.AssertIsEqual(fc.LinearFormRLC, expectedRLC)
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

	for i := 0; i < numVariables; i++ {
		res[numVariables-1-i] = current
		current = api.Mul(current, current)
	}

	return res
}
