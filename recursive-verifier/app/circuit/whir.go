package circuit

import (
	"fmt"
	"math/big"

	"reilabs/whir-verifier-circuit/app/utilities"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

// NewWhirParams creates a new WHIRParams instance from the given configuration.
// It processes the folding factors and calculates domain sizes based on the provided config.
func NewWhirParams(cfg WHIRConfig) WHIRParams {
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

// RunZKWhir executes the zero-knowledge WHIR protocol for proof verification.
// It processes multiple rounds of sumcheck protocols and merkle tree verifications
// to verify the given circuit proof against the provided parameters.
func RunZKWhir(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
	circuit Merkle,
	firstRound Merkle,
	whirParams WHIRParams,
	linearStatementEvaluations [][]frontend.Variable,
	linearStatementValuesAtPoints []frontend.Variable, // weights.evaluate(random_point) - this is what needs to be done 
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
			err = utilities.IsEqual(api, uapi, mainRoundData.StirChallengesPoints[r], firstRound.LeafIndexes[0])
			if err != nil {
				return
			}
			err = verifyMerkleTreeProofs(api, uapi, sc, firstRound.LeafIndexes[0], firstRound.Leaves[0], firstRound.LeafSiblingHashes[0], firstRound.AuthPaths[0], rootHashes)
			if err != nil {
				return
			}
			mainRoundData.StirChallengesPoints[r] = make([]frontend.Variable, len(firstRound.LeafIndexes[r]))
			for index := range firstRound.LeafIndexes[r] {
				mainRoundData.StirChallengesPoints[r][index] = utilities.Exponent(api, uapi, expDomainGenerator, firstRound.LeafIndexes[r][index])
			}
		} else {
			err = utilities.IsEqual(api, uapi, mainRoundData.StirChallengesPoints[r], circuit.LeafIndexes[r-1])
			if err != nil {
				return
			}
			err = verifyMerkleTreeProofs(api, uapi, sc, circuit.LeafIndexes[r-1], roundAnswers[r], circuit.LeafSiblingHashes[r-1], circuit.AuthPaths[r-1], rootHashList[r-1])
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

// RunZKWhirBatch executes batch WHIR verification for N commitments.
// This is used when num_challenges > 0 (batch commitment mode).
func RunZKWhirBatch(
	api frontend.API,
	arthur gnarkNimue.Arthur,
	uapi *uints.BinaryField[uints.U64],
	sc *skyscraper.Skyscraper,
	// N commitments data for round 0
	firstRounds []Merkle,
	batchingRandomnesses []frontend.Variable,
	initialOODQueries [][]frontend.Variable,
	initialOODAnswers [][][]frontend.Variable,
	rootHashes []frontend.Variable,
	// Batched polynomial merkle for rounds 1+
	batchedMerkle Merkle,
	// Statement evaluations per commitment
	linearStatementEvals [][][]frontend.Variable, // [commitment_idx][f/g][eval_idx]
	// Common parameters
	whirParams WHIRParams,
	linearStatementValuesAtPoints []frontend.Variable,
	publicInputs PublicInputs,
) (totalFoldingRandomness []frontend.Variable, err error) {
	numPolynomials := len(firstRounds)
	if numPolynomials == 0 {
		return nil, fmt.Errorf("RunZKWhirBatch: need at least one commitment")
	}

	// Step 1: Reduce OOD answers for each commitment
	initialOODs := make([][]frontend.Variable, numPolynomials)
	for i := 0; i < numPolynomials; i++ {
		initialOODs[i] = oodAnswers(api, initialOODAnswers[i], batchingRandomnesses[i])
	}

	// Step 2: Count total constraints (OOD + statement per commitment)
	numOOD := 0
	for i := 0; i < numPolynomials; i++ {
		numOOD += len(initialOODQueries[i])
	}
	numStatementConstraints := numPolynomials * 3 // 3 per commitment (Az, Bz, Cz)
	numConstraints := numOOD + numStatementConstraints

	// Step 3: Read N×M evaluation matrix from transcript
	evalMatrix := make([][]frontend.Variable, numPolynomials)
	for i := 0; i < numPolynomials; i++ {
		evalMatrix[i] = make([]frontend.Variable, numConstraints)
		if err = arthur.FillNextScalars(evalMatrix[i]); err != nil {
			return nil, err
		}
	}

	// Step 4: Squeeze batching randomness γ
	gamma := make([]frontend.Variable, 1)
	if err = arthur.FillChallengeScalars(gamma); err != nil {
		return nil, err
	}
	batchGamma := gamma[0]

	// Step 5: RLC-combine constraint evaluations: combined[j] = Σᵢ γⁱ·eval[i][j]
	combinedEvals := make([]frontend.Variable, numConstraints)
	for j := 0; j < numConstraints; j++ {
		combined := frontend.Variable(0)
		gammaPow := frontend.Variable(1)
		for i := 0; i < numPolynomials; i++ {
			combined = api.Add(combined, api.Mul(gammaPow, evalMatrix[i][j]))
			gammaPow = api.Mul(gammaPow, batchGamma)
		}
		combinedEvals[j] = combined
	}

	// Step 6: Initial combination randomness and claimed sum
	initialCombRandomness, err := GenerateCombinationRandomness(api, arthur, numConstraints)
	if err != nil {
		return nil, err
	}
	lastEval := utilities.DotProduct(api, initialCombRandomness, combinedEvals)

	// Step 7: Initial sumcheck
	initialFoldingRandomness, lastEval, err := runWhirSumcheckRounds(
		api, lastEval, arthur, whirParams.FoldingFactorArray[0], 3)
	if err != nil {
		return nil, err
	}
	totalFoldingRandomness = initialFoldingRandomness

	// ========================================
	// ROUND 0: Batch-specific verification
	// Verify STIR queries against ALL N original trees
	// ========================================

	// Read commitment to batched folded polynomial (used in rounds 1+)
	batchedRootHash := make([]frontend.Variable, 1)
	if err = arthur.FillNextScalars(batchedRootHash); err != nil {
		return nil, err
	}

	// Read OOD for batched polynomial
	round0OODPoints, round0OODAnswers, err := fillInOODPointsAndAnswers(
		whirParams.RoundParametersOODSamples[0], arthur)
	if err != nil {
		return nil, err
	}

	// PoW for round 0
	if err = RunPoW(api, sc, arthur, whirParams.PowBits[0]); err != nil {
		return nil, err
	}

	// Get STIR challenge indices
	domainSize := whirParams.DomainSize
	foldSize := 1 << whirParams.FoldingFactorArray[0]
	stirChallengeIndices, err := getStirChallenges(
		api, arthur, whirParams.RoundParametersNumOfQueries[0], domainSize, foldSize)
	if err != nil {
		return nil, err
	}

	expDomainGenerator := utilities.Exponent(api, uapi,
		whirParams.StartingDomainBackingDomainGenerator,
		uints.NewU64(uint64(foldSize)))

	// Verify Merkle proofs in ALL N original trees
	collapsedAnswers := make([][][]frontend.Variable, numPolynomials)
	for i := 0; i < numPolynomials; i++ {
		// Check indices match
		err = utilities.IsEqual(api, uapi, stirChallengeIndices, firstRounds[i].LeafIndexes[0])
		if err != nil {
			return nil, err
		}
		// Verify Merkle proofs
		err = verifyMerkleTreeProofs(api, uapi, sc,
			firstRounds[i].LeafIndexes[0],
			firstRounds[i].Leaves[0],
			firstRounds[i].LeafSiblingHashes[0],
			firstRounds[i].AuthPaths[0],
			rootHashes[i])
		if err != nil {
			return nil, err
		}
		// Collapse batched leaves using commitment's batching randomness
		collapsedAnswers[i] = rlcBatchedLeaves(api,
			firstRounds[i].Leaves[0], foldSize, whirParams.BatchSize, batchingRandomnesses[i])
	}

	// RLC-combine answers across N polynomials: combined[q][f] = Σᵢ γⁱ·collapsed[i][q][f]
	numQueries := len(collapsedAnswers[0])
	combinedAnswers := make([][]frontend.Variable, numQueries)
	for q := 0; q < numQueries; q++ {
		combinedAnswers[q] = make([]frontend.Variable, foldSize)
		for f := 0; f < foldSize; f++ {
			combined := frontend.Variable(0)
			gammaPow := frontend.Variable(1)
			for i := 0; i < numPolynomials; i++ {
				combined = api.Add(combined, api.Mul(gammaPow, collapsedAnswers[i][q][f]))
				gammaPow = api.Mul(gammaPow, batchGamma)
			}
			combinedAnswers[q][f] = combined
		}
	}

	// Compute fold evaluations from combined answers
	computedFold := computeFold(combinedAnswers, initialFoldingRandomness, api)

	// Convert STIR indices to domain points
	stirChallengePoints := make([]frontend.Variable, numQueries)
	for idx := range firstRounds[0].LeafIndexes[0] {
		stirChallengePoints[idx] = utilities.Exponent(api, uapi, expDomainGenerator, firstRounds[0].LeafIndexes[0][idx])
	}

	// Combination randomness for round 0 constraints (OOD + STIR)
	round0CombRandomness, err := GenerateCombinationRandomness(api, arthur,
		len(round0OODPoints)+len(computedFold))
	if err != nil {
		return nil, err
	}

	// Update claimed sum with OOD and STIR constraints
	lastEval = api.Add(lastEval, calculateShiftValue(round0OODAnswers, round0CombRandomness, computedFold, api))

	// Sumcheck for round 0
	round0FoldingRandomness, lastEval, err := runWhirSumcheckRounds(
		api, lastEval, arthur, whirParams.FoldingFactorArray[1], 3)
	if err != nil {
		return nil, err
	}
	totalFoldingRandomness = append(totalFoldingRandomness, round0FoldingRandomness...)

	// Update domain
	domainSize /= 2
	expDomainGenerator = api.Mul(expDomainGenerator, expDomainGenerator)

	// Prepare for rounds 1+
	mainRoundData := generateEmptyMainRoundData(whirParams)
	mainRoundData.OODPoints[0] = round0OODPoints
	mainRoundData.StirChallengesPoints[0] = stirChallengePoints
	mainRoundData.CombinationRandomness[0] = round0CombRandomness

	rootHashList := make([]frontend.Variable, whirParams.ParamNRounds)
	rootHashList[0] = batchedRootHash[0]

	// Update computedFold for next round
	if len(batchedMerkle.Leaves) > 0 {
		computedFold = computeFold(batchedMerkle.Leaves[0], round0FoldingRandomness, api)
	}

	// ========================================
	// ROUNDS 1+: Standard WHIR on batched polynomial
	// ========================================
	for r := 1; r < whirParams.ParamNRounds; r++ {
		rootHash := make([]frontend.Variable, 1)
		if err = arthur.FillNextScalars(rootHash); err != nil {
			return nil, err
		}
		rootHashList[r] = rootHash[0]

		var roundOODAnswers []frontend.Variable
		mainRoundData.OODPoints[r], roundOODAnswers, err = fillInOODPointsAndAnswers(
			whirParams.RoundParametersOODSamples[r], arthur)
		if err != nil {
			return nil, err
		}

		if err = RunPoW(api, sc, arthur, whirParams.PowBits[r]); err != nil {
			return nil, err
		}

		// Get STIR challenges and verify against batched merkle
		mainRoundData.StirChallengesPoints[r], err = getStirChallenges(
			api, arthur, whirParams.RoundParametersNumOfQueries[r], domainSize, 1<<whirParams.FoldingFactorArray[r])
		if err != nil {
			return nil, err
		}

		// Verify indices match batched merkle
		err = utilities.IsEqual(api, uapi, mainRoundData.StirChallengesPoints[r], batchedMerkle.LeafIndexes[r-1])
		if err != nil {
			return nil, err
		}

		// Verify Merkle proofs against batched tree
		err = verifyMerkleTreeProofs(api, uapi, sc,
			batchedMerkle.LeafIndexes[r-1],
			batchedMerkle.Leaves[r-1],
			batchedMerkle.LeafSiblingHashes[r-1],
			batchedMerkle.AuthPaths[r-1],
			rootHashList[r-1])
		if err != nil {
			return nil, err
		}

		// Convert indices to domain points
		mainRoundData.StirChallengesPoints[r] = make([]frontend.Variable, len(batchedMerkle.LeafIndexes[r-1]))
		for index := range batchedMerkle.LeafIndexes[r-1] {
			mainRoundData.StirChallengesPoints[r][index] = utilities.Exponent(api, uapi, expDomainGenerator, batchedMerkle.LeafIndexes[r-1][index])
		}

		mainRoundData.CombinationRandomness[r], err = GenerateCombinationRandomness(
			api, arthur, len(mainRoundData.OODPoints[r])+len(computedFold))
		if err != nil {
			return nil, err
		}

		lastEval = api.Add(lastEval, calculateShiftValue(roundOODAnswers, mainRoundData.CombinationRandomness[r], computedFold, api))

		var roundFoldingRandomness []frontend.Variable
		roundFoldingRandomness, lastEval, err = runWhirSumcheckRounds(api, lastEval, arthur, whirParams.FoldingFactorArray[r], 3)
		if err != nil {
			return nil, err
		}

		if r < len(batchedMerkle.Leaves) {
			computedFold = computeFold(batchedMerkle.Leaves[r], roundFoldingRandomness, api)
		}
		totalFoldingRandomness = append(totalFoldingRandomness, roundFoldingRandomness...)

		domainSize /= 2
		expDomainGenerator = api.Mul(expDomainGenerator, expDomainGenerator)
	}

	// ========================================
	// FINAL ROUND
	// ========================================
	finalCoefficients := make([]frontend.Variable, 1<<whirParams.FinalSumcheckRounds)
	if err = arthur.FillNextScalars(finalCoefficients); err != nil {
		return nil, err
	}

	if err = RunPoW(api, sc, arthur, whirParams.FinalPowBits); err != nil {
		return nil, err
	}

	// Final STIR queries
	finalLeafIdx := len(batchedMerkle.LeafIndexes) - 1
	finalRandomnessPoints, err := GenerateStirChallengePoints(api, arthur,
		whirParams.FinalQueries,
		batchedMerkle.LeafIndexes[finalLeafIdx],
		domainSize, uapi, expDomainGenerator,
		whirParams.FoldingFactorArray[whirParams.ParamNRounds])
	if err != nil {
		return nil, err
	}

	// Verify final coefficients match folds
	finalEvaluations := utilities.UnivarPoly(api, finalCoefficients, finalRandomnessPoints)
	for foldIndex := range computedFold {
		api.AssertIsEqual(computedFold[foldIndex], finalEvaluations[foldIndex])
	}

	// Final sumcheck
	finalSumcheckRandomness, lastEval, err := runWhirSumcheckRounds(api, lastEval, arthur, whirParams.FinalSumcheckRounds, 3)
	if err != nil {
		return nil, err
	}
	totalFoldingRandomness = append(totalFoldingRandomness, finalSumcheckRandomness...)

	// Final PoW
	if whirParams.FinalFoldingPowBits > 0 {
		_, _, err = utilities.PoW(api, sc, arthur, whirParams.FinalFoldingPowBits)
		if err != nil {
			return nil, err
		}
	}

	// Reverse randomness for W-poly evaluation
	totalFoldingRandomness = utilities.Reverse(totalFoldingRandomness)

	// Build combined initial sumcheck data
	allOODQueries := make([]frontend.Variable, 0)
	for i := 0; i < numPolynomials; i++ {
		allOODQueries = append(allOODQueries, initialOODQueries[i]...)
	}
	initialSumcheckData := InitialSumcheckData{
		InitialOODQueries:            allOODQueries,
		InitialCombinationRandomness: initialCombRandomness,
	}

	// Compute W-poly evaluation
	evaluationOfWPoly := computeWPoly(
		api,
		whirParams,
		initialSumcheckData,
		mainRoundData,
		totalFoldingRandomness,
		linearStatementValuesAtPoints,
	)

	// Final check
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

// RunPoW executes a proof-of-work challenge if the difficulty is greater than zero.
// This is used as part of the Fiat-Shamir transformation to prevent malicious prover behavior.
func RunPoW(api frontend.API, sc *skyscraper.Skyscraper, arthur gnarkNimue.Arthur, difficulty int) error {
	if difficulty > 0 {
		_, _, err := utilities.PoW(api, sc, arthur, difficulty)
		if err != nil {
			return err
		}
	}
	return nil
}

// GenerateStirChallengePoints generates the stir challenge points for the given parameters.
// It calculates the folding factor power and generates the stir challenges for the given leaf indexes.
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

	err = utilities.IsEqual(api, uapi, finalIndexes, leafIndexes)
	if err != nil {
		return nil, err
	}

	finalRandomnessPoints := make([]frontend.Variable, len(leafIndexes))

	for index := range leafIndexes {
		finalRandomnessPoints[index] = utilities.Exponent(api, uapi, expDomainGenerator, leafIndexes[index])
	}

	return finalRandomnessPoints, nil
}

// GenerateCombinationRandomness generates the combination randomness for the given parameters.
// It generates a random scalar and expands it to the required length.
func GenerateCombinationRandomness(api frontend.API, arthur gnarkNimue.Arthur, randomnessLength int) ([]frontend.Variable, error) {
	combRandomnessGen := make([]frontend.Variable, 1)
	if err := arthur.FillChallengeScalars(combRandomnessGen); err != nil {
		return nil, err
	}

	combinationRandomness := utilities.ExpandRandomness(api, combRandomnessGen[0], randomnessLength)
	return combinationRandomness, nil
}
