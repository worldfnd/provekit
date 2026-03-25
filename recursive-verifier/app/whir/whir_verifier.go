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
) (totalFoldingRandomness []frontend.Variable, err error) {

	numVectors := params.BatchSize

	// Complete the constraint and evaluation matrix with OODs and their cross-terms.
	numOODConstraints := 0
	var oodMatrix []frontend.Variable
	vectorOffset := 0
	committedOODRows := commitment.OodAnswers
	numVectorsPerCommitment := params.BatchSize
	for i := 0; i < params.CommittmentOODSamples; i++ {
		for j := 0; j < numVectors; j++ {
			if j >= vectorOffset && j < numVectorsPerCommitment+vectorOffset {
				oodMatrix = append(oodMatrix, committedOODRows[i*numVectorsPerCommitment+(j-vectorOffset)])
			} else {
				// Cross-term: read from transcript (absorb into sponge).
				crossTerm := make([]frontend.Variable, 1)
				if err = nimue.FillNextScalars(crossTerm); err != nil {
					return nil, fmt.Errorf("ood cross-term: %w", err)
				}
				api.Println("crossTerm", crossTerm[0])
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
	api.Println("oodPoints", oodPoints)
	api.Println("oodMatrix", oodMatrix)
	// Random linear combination of the vectors.
	vectorRlcCoeffs, err := geometricChallenge(api, nimue, numVectors)
	if err != nil {
		return nil, fmt.Errorf("vector_rlc: %w", err)
	}
	_ = vectorRlcCoeffs

	// Random linear combination of the constraints.
	numLinearForms := len(statements)
	constraintRlcCoeffs, err := geometricChallenge(api, nimue, numOODConstraints+numLinearForms)
	if err != nil {
		return nil, fmt.Errorf("constraint_rlc: %w", err)
	}
	oodsRlcCoeffs := constraintRlcCoeffs[:numOODConstraints]
	initialFormRlcCoeffs := constraintRlcCoeffs[numOODConstraints:]

	// Compute "the sum" (mirrors Rust whir::verifier lines 110-118)
	theSum := frontend.Variable(0)
	// for i, rlcCoeff := range initialFormRlcCoeffs {
	// 	evaluationRow := make([]frontend.Variable, params.BatchSize)
	// 	for j := range evaluationRow {
	// 		evaluationRow[j] = statements[i].Constraints[j].Evaluation
	// 	}
	// 	theSum = api.Add(theSum, api.Mul(rlcCoeff, DotProduct(api, vectorRlcCoeffs, evaluationRow)))
	// }
	// for i, rlcCoeff := range oodsRlcCoeffs {
	// 	oodsRow := oodMatrix[i*numVectors : (i+1)*numVectors]
	// 	theSum = api.Add(theSum, api.Mul(rlcCoeff, DotProduct(api, vectorRlcCoeffs, oodsRow)))
	// }

	// Perform the initial sumcheck
	initialSumcheckData, theSum, initialSumcheckFoldingRandomness, err := initialSumcheck(api, nimue, theSum, commitment.OodPoints, oodsRlcCoeffs, initialFormRlcCoeffs, params)
	if err != nil {
		return
	}

	// TODO: Re-enable once hint infrastructure is wired up.
	// foldSize := 1 << params.FoldingFactorArray[0]
	// numQueries := params.RoundParametersNumOfQueries[0]
	// initialLeaves := readLeavesFromHints(hr, numQueries, params.BatchSize*foldSize)

	mainRoundData := generateEmptyMainRoundData(params)
	expDomainGenerator := ExponentVar(api, params.StartingDomainBackingDomainGenerator, frontend.Variable(1<<params.FoldingFactorArray[0]), bits.Len(uint(params.DomainSize)))
	domainSize := params.DomainSize

	totalFoldingRandomness = initialSumcheckFoldingRandomness

	var prevRootHash frontend.Variable

	for r := range params.ParamNRounds {
		// Receive round commitment
		rootHash := make([]frontend.Variable, 1)
		if err = nimue.FillNextScalars(rootHash); err != nil {
			return nil, fmt.Errorf("round %d root: %w", r, err)
		}
		api.Println("rootHash", rootHash)

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
		api.Println("roundOODPoints", roundOODPoints)
		api.Println("roundOODAnswers", roundOODAnswers)
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

		// TODO: Re-enable Merkle/leaf verification once hints are wired up.
		_ = stirIndexes

		prevRootHash = rootHash[0]

		// Compute domain evaluation points from indices
		numBits := bits.Len(uint(domainSize - 1))
		mainRoundData.StirChallengesPoints[r] = make([]frontend.Variable, len(stirIndexes))
		for index, idx := range stirIndexes {
			mainRoundData.StirChallengesPoints[r][index] = ExponentVar(api, expDomainGenerator, idx, numBits)
		}

		// Constraint values = OOD values + in-domain zero placeholders.
		numInDomainQueries := len(stirIndexes)
		constraintValues := make([]frontend.Variable, 0, len(roundOODAnswers)+numInDomainQueries)
		constraintValues = append(constraintValues, roundOODAnswers...)
		for range numInDomainQueries {
			constraintValues = append(constraintValues, frontend.Variable(0))
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

	// TODO: Re-enable final round leaf/Merkle verification once hints are wired up.
	_ = prevRootHash
	_ = finalRandomnessPoints
	_ = finalVector

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

	// TODO: Re-enable deferred evaluation check and final equation once hints are wired up.
	_ = initialSumcheckData
	_ = mainRoundData
	_ = initialFormRlcCoeffs
	_ = numLinearForms
	_ = finalSumcheckRandomness

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

	for i := 0; i < numVariables; i++ {
		res[numVariables-1-i] = current
		current = api.Mul(current, current)
	}

	return res
}
