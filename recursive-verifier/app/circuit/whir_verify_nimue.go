package circuit

import (
	"fmt"
	"math/big"
	"math/bits"

	"reilabs/whir-verifier-circuit/app/utilities"
	"reilabs/whir-verifier-circuit/app/whir"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

// ---------------------------------------------------------------------------
// Circuit-level WHIR verification using gnark-nimue transcript.
// Adapted from the gnark whir package (recursive-verifier/app/whir/) to use
// nimue instead of keccacheck/transcript.Verifier.
// ---------------------------------------------------------------------------

// NimueHintReader provides on-demand access to the WHIR hint byte stream
// by issuing gnark NewHint calls. Mirrors whir.HintReader but avoids the
// keccacheck dependency.
type NimueHintReader struct {
	api        frontend.API
	hintInputs []frontend.Variable
	vecHint    solver.Hint
	hashHint   solver.Hint
	callIndex  int
}

// NewNimueHintReader creates a hint reader for WHIR proof data.
func NewNimueHintReader(api frontend.API, hintInputs []frontend.Variable, vecHint, hashHint solver.Hint) *NimueHintReader {
	return &NimueHintReader{
		api:        api,
		hintInputs: hintInputs,
		vecHint:    vecHint,
		hashHint:   hashHint,
	}
}

// ReadVec reads n field elements from a Vec block in the hint stream.
func (h *NimueHintReader) ReadVec(n int) []frontend.Variable {
	inputs := append(h.hintInputs, frontend.Variable(h.callIndex), frontend.Variable(0))
	h.callIndex++
	results, err := h.api.Compiler().NewHint(h.vecHint, n, inputs...)
	if err != nil {
		panic(fmt.Sprintf("NimueHintReader.ReadVec failed: %v", err))
	}
	return results
}

// ReadHash reads a single hash from the hint stream.
func (h *NimueHintReader) ReadHash() frontend.Variable {
	inputs := append(h.hintInputs, frontend.Variable(h.callIndex), frontend.Variable(1))
	h.callIndex++
	results, err := h.api.Compiler().NewHint(h.hashHint, 1, inputs...)
	if err != nil {
		panic(fmt.Sprintf("NimueHintReader.ReadHash failed: %v", err))
	}
	return results[0]
}

// ---------------------------------------------------------------------------
// ParsedCommitmentNimue is the circuit-level parsed commitment.
// ---------------------------------------------------------------------------

// ParsedCommitmentNimue mirrors the gnark whir ParsedCommitment but lives
// in the circuit package to avoid importing the whir package.
type ParsedCommitmentNimue struct {
	Root       frontend.Variable
	OodPoints  []frontend.Variable
	OodAnswers []frontend.Variable // flat: outDomainSamples * batchSize
}

// WhirStatement represents an external linear form constraint for WHIR.
type WhirStatement struct {
	Evaluation frontend.Variable // claimed evaluation value
}

// ---------------------------------------------------------------------------
// nimueReceiveCommitment reads a round commitment from the nimue transcript.
// ---------------------------------------------------------------------------

func nimueReceiveCommitment(
	nimue gnarkNimue.Nimue,
	oodSamples int,
) (ParsedCommitmentNimue, error) {
	rootHash := make([]frontend.Variable, 1)
	if err := nimue.FillNextScalars(rootHash); err != nil {
		return ParsedCommitmentNimue{}, fmt.Errorf("root hash: %w", err)
	}

	oodPoints := make([]frontend.Variable, oodSamples)
	if oodSamples > 0 {
		if err := nimue.FillChallengeScalars(oodPoints); err != nil {
			return ParsedCommitmentNimue{}, fmt.Errorf("ood points: %w", err)
		}
	}

	oodAnswers := make([]frontend.Variable, oodSamples)
	if oodSamples > 0 {
		if err := nimue.FillNextScalars(oodAnswers); err != nil {
			return ParsedCommitmentNimue{}, fmt.Errorf("ood answers: %w", err)
		}
	}

	return ParsedCommitmentNimue{
		Root:       rootHash[0],
		OodPoints:  oodPoints,
		OodAnswers: oodAnswers,
	}, nil
}

// ---------------------------------------------------------------------------
// nimueGeometricChallenge mirrors Rust geometric_challenge using nimue.
// Returns [1] for count <= 1, or [1, x, x^2, ...] for count > 1.
// ---------------------------------------------------------------------------

func nimueGeometricChallenge(
	api frontend.API,
	nimue gnarkNimue.Nimue,
	count int,
) ([]frontend.Variable, error) {
	switch {
	case count == 0:
		return nil, nil
	case count == 1:
		return []frontend.Variable{frontend.Variable(1)}, nil
	default:
		x := make([]frontend.Variable, 1)
		if err := nimue.FillChallengeScalars(x); err != nil {
			return nil, err
		}
		api.Println("x", x)
		return utilities.ExpandRandomness(api, x[0], count), nil
	}
}

// ---------------------------------------------------------------------------
// nimueWhirSumcheckRounds mirrors the WHIR quadratic sumcheck verifier.
// Each round reads c0, c2 from the transcript, derives c1, and squeezes
// a folding challenge.
// ---------------------------------------------------------------------------

func nimueWhirSumcheckRounds(
	api frontend.API,
	nimue gnarkNimue.Nimue,
	sum frontend.Variable,
	numRounds int,
) ([]frontend.Variable, frontend.Variable, error) {
	foldingRandomness := make([]frontend.Variable, numRounds)

	for i := range numRounds {
		// Read c0 and c2
		coeffs := make([]frontend.Variable, 2)
		if err := nimue.FillNextScalars(coeffs); err != nil {
			return nil, nil, fmt.Errorf("sumcheck round %d: %w", i, err)
		}
		c0 := coeffs[0]
		c2 := coeffs[1]
		api.Println("c0", c0)
		api.Println("c2", c2)
		// c1 = sum - 2*c0 - c2
		c1 := api.Sub(sum, api.Add(api.Add(c0, c0), c2))

		// Squeeze folding randomness
		rBuf := make([]frontend.Variable, 1)
		if err := nimue.FillChallengeScalars(rBuf); err != nil {
			return nil, nil, fmt.Errorf("sumcheck round %d challenge: %w", i, err)
		}
		api.Println("rBuf", rBuf)
		foldingRandomness[i] = rBuf[0]

		// sum = P(r) = (c2*r + c1)*r + c0
		r := foldingRandomness[i]
		sum = api.Add(api.Mul(api.Add(api.Mul(c2, r), c1), r), c0)
	}

	return foldingRandomness, sum, nil
}

// ---------------------------------------------------------------------------
// computeEqWeightsCircuit computes eq(point, p) for all binary points p.
// ---------------------------------------------------------------------------

func computeEqWeightsCircuit(api frontend.API, point []frontend.Variable) []frontend.Variable {
	n := len(point)
	size := 1 << n
	result := make([]frontend.Variable, size)
	result[0] = frontend.Variable(1)
	cur := 1
	for i := 0; i < n; i++ {
		for j := cur - 1; j >= 0; j-- {
			lo := api.Mul(result[j], api.Sub(frontend.Variable(1), point[i]))
			hi := api.Sub(result[j], lo)
			result[2*j] = lo
			result[2*j+1] = hi
		}
		cur *= 2
	}
	return result
}

// ---------------------------------------------------------------------------
// tensorProductCircuit computes the Kronecker product of two vectors.
// ---------------------------------------------------------------------------

func tensorProductCircuit(api frontend.API, a, b []frontend.Variable) []frontend.Variable {
	result := make([]frontend.Variable, len(a)*len(b))
	for i, x := range a {
		for j, y := range b {
			result[i*len(b)+j] = api.Mul(x, y)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// univarMleEvaluateCircuit computes the MLE of the univariate evaluation
// linear form: Π_i ((1 - r_i) + r_i * point^(2^i))
// ---------------------------------------------------------------------------

func univarMleEvaluateCircuit(api frontend.API, univarPoint frontend.Variable, point []frontend.Variable) frontend.Variable {
	n := len(point)
	result := frontend.Variable(1)
	x2i := univarPoint
	for i := n - 1; i >= 0; i-- {
		factor := api.Add(api.Sub(frontend.Variable(1), point[i]), api.Mul(point[i], x2i))
		result = api.Mul(result, factor)
		x2i = api.Mul(x2i, x2i)
	}
	return result
}

// ---------------------------------------------------------------------------
// exponentVarCircuit computes base^exp using square-and-multiply.
// ---------------------------------------------------------------------------

func exponentVarCircuit(api frontend.API, base frontend.Variable, exp frontend.Variable, numBits int) frontend.Variable {
	expBits := api.ToBinary(exp, numBits)
	output := frontend.Variable(1)
	multiply := base
	for i := range expBits {
		output = api.Select(expBits[i], api.Mul(output, multiply), output)
		multiply = api.Mul(multiply, multiply)
	}
	return output
}

// ---------------------------------------------------------------------------
// nimueReadLeavesFromHints reads leaf values from the hint stream.
// ---------------------------------------------------------------------------

func nimueReadLeavesFromHints(hr *NimueHintReader, numLeaves, numCols int) [][]frontend.Variable {
	flat := hr.ReadVec(numLeaves * numCols)
	leaves := make([][]frontend.Variable, numLeaves)
	for i := range leaves {
		leaves[i] = flat[i*numCols : (i+1)*numCols]
	}
	return leaves
}

// ---------------------------------------------------------------------------
// nimueVerifyMerklePaths verifies Merkle membership proofs using Skyscraper.
// ---------------------------------------------------------------------------

// nimueVerifyMerklePaths verifies Merkle membership proofs using Skyscraper CompressV2.
// Each leaf is hashed, then the auth path is traversed to the root.
// Parameters:
//   - leaves: [query_idx][fold_element_idx] - leaf values from submatrix
//   - leafIndexes: [query_idx] - leaf positions in the folded domain
//   - siblingHashes: [query_idx] - sibling hashes at the leaf level
//   - authPaths: [query_idx][level] - authentication path hashes
//   - rootHash: expected Merkle root
func nimueVerifyMerklePaths(
	api frontend.API,
	sc *skyscraper.Skyscraper,
	leaves [][]frontend.Variable,
	leafIndexes []frontend.Variable,
	siblingHashes []frontend.Variable,
	authPaths [][]frontend.Variable,
	rootHash frontend.Variable,
	treeHeight int,
) {
	for i := range leaves {
		leafIndexBits := api.ToBinary(leafIndexes[i], treeHeight)

		// Hash leaf elements into a single commitment.
		claimedLeafHash := sc.CompressV2(leaves[i][0], leaves[i][1])
		for x := 2; x < len(leaves[i]); x++ {
			claimedLeafHash = sc.CompressV2(claimedLeafHash, leaves[i][x])
		}

		// Level 0: combine with sibling.
		dir := leafIndexBits[0]
		left := api.Select(dir, siblingHashes[i], claimedLeafHash)
		right := api.Select(dir, claimedLeafHash, siblingHashes[i])
		currentHash := sc.CompressV2(left, right)

		// Remaining levels.
		for level := 1; level < treeHeight; level++ {
			indexBit := api.And(leafIndexBits[level], 1)
			left = api.Select(indexBit, authPaths[i][level-1], currentHash)
			right = api.Select(indexBit, currentHash, authPaths[i][level-1])
			currentHash = sc.CompressV2(left, right)
		}

		api.AssertIsEqual(currentHash, rootHash)
	}
}

// ---------------------------------------------------------------------------
// MainRoundDataNimue holds per-round constraint data for WHIR.
// ---------------------------------------------------------------------------

type MainRoundDataNimue struct {
	OODPoints             [][]frontend.Variable
	StirChallengesPoints  [][]frontend.Variable
	CombinationRandomness [][]frontend.Variable
}

type InitialSumcheckDataNimue struct {
	InitialOODQueries            []frontend.Variable
	InitialCombinationRandomness []frontend.Variable
}

// ---------------------------------------------------------------------------
// VerifyWhirNimue is the circuit-level WHIR verification using nimue.
// Adapted from gnark whir's VerifyWhir (whir_verifier.go).
//
// Parameters:
//   - commitment: parsed initial commitment (root, OOD points, OOD answers)
//   - statements: external linear form evaluations to verify
//   - params: WHIR protocol parameters (circuit.WHIRParams)
//   - hr: hint reader for Merkle proofs and leaf data
// ---------------------------------------------------------------------------

func VerifyWhirNimue(
	api frontend.API,
	sc *skyscraper.Skyscraper,
	nimue gnarkNimue.Nimue,
	commitment ParsedCommitmentNimue,
	statements []WhirStatement,
	params WHIRParams,
	// hr *NimueHintReader,
) (totalFoldingRandomness []frontend.Variable, err error) {

	numVectors := params.BatchSize

	// ---------------------------------------------------------------
	// 1. Complete OOD evaluation matrix (single commitment, no cross-terms)
	// ---------------------------------------------------------------
	numOODConstraints := 0
	var oodMatrix []frontend.Variable
	for i := 0; i < params.CommittmentOODSamples; i++ {
		for j := 0; j < numVectors; j++ {
			oodMatrix = append(oodMatrix, commitment.OodAnswers[i*numVectors+j])
		}
		numOODConstraints++
	}

	// Extract OOD multilinear points from univariate challenge points
	oodPoints := make([][]frontend.Variable, len(commitment.OodPoints))
	for i, point := range commitment.OodPoints {
		oodPoints[i] = utilities.ExpandFromUnivariate(api, point, params.MVParamsNumberOfVariables)
	}

	// ---------------------------------------------------------------
	// 2. Vector RLC
	// ---------------------------------------------------------------
	vectorRlcCoeffs, err := nimueGeometricChallenge(api, nimue, numVectors)
	if err != nil {
		return nil, fmt.Errorf("vector_rlc: %w", err)
	}

	// ---------------------------------------------------------------
	// 3. Constraint RLC
	// ---------------------------------------------------------------
	numLinearForms := len(statements)
	totalConstraints := numOODConstraints + numLinearForms
	constraintRlcCoeffs, err := nimueGeometricChallenge(api, nimue, totalConstraints)
	if err != nil {
		return nil, fmt.Errorf("constraint_rlc: %w", err)
	}

	oodsRlcCoeffs := constraintRlcCoeffs[:numOODConstraints]
	initialFormRlcCoeffs := constraintRlcCoeffs[numOODConstraints:]

	// ---------------------------------------------------------------
	// 4. Compute "the sum"
	// ---------------------------------------------------------------
	theSum := frontend.Variable(0)

	// Contribution from external linear forms.
	// For batchSize=1 (single commitment), each statement maps to one evaluation.
	// The dot product with vectorRlcCoeffs=[1] simplifies to just the evaluation.
	for i, rlcCoeff := range initialFormRlcCoeffs {
		theSum = api.Add(theSum, api.Mul(rlcCoeff, statements[i].Evaluation))
	}

	// Contribution from OOD constraints.
	// For batchSize=1, each OOD row has one element.
	for i, rlcCoeff := range oodsRlcCoeffs {
		if numVectors == 1 {
			theSum = api.Add(theSum, api.Mul(rlcCoeff, oodMatrix[i]))
		} else {
			oodsRow := oodMatrix[i*numVectors : (i+1)*numVectors]
			theSum = api.Add(theSum, api.Mul(rlcCoeff, utilities.DotProduct(api, vectorRlcCoeffs, oodsRow)))
		}
	}

	// ---------------------------------------------------------------
	// 5. Initial sumcheck
	// ---------------------------------------------------------------
	initialSumcheckFoldingRandomness, theSum, err := nimueWhirSumcheckRounds(api, nimue, theSum, params.FoldingFactorArray[0])
	if err != nil {
		return nil, fmt.Errorf("initial sumcheck: %w", err)
	}

	initialSumcheckData := InitialSumcheckDataNimue{
		InitialOODQueries:            commitment.OodPoints,
		InitialCombinationRandomness: constraintRlcCoeffs,
	}

	// TODO: Re-enable once hint infrastructure is wired up.
	// foldSize := 1 << params.FoldingFactorArray[0]
	// numQueries := params.RoundParametersNumOfQueries[0]
	// initialLeaves := nimueReadLeavesFromHints(hr, numQueries, params.BatchSize*foldSize)

	mainRoundData := MainRoundDataNimue{
		OODPoints:             make([][]frontend.Variable, params.ParamNRounds),
		StirChallengesPoints:  make([][]frontend.Variable, params.ParamNRounds),
		CombinationRandomness: make([][]frontend.Variable, params.ParamNRounds),
	}

	expDomainGenerator := exponentVarCircuit(api, params.StartingDomainBackingDomainGenerator, frontend.Variable(1<<params.FoldingFactorArray[0]), bits.Len(uint(params.DomainSize)))
	domainSize := params.DomainSize

	totalFoldingRandomness = initialSumcheckFoldingRandomness

	var prevRootHash frontend.Variable

	// ---------------------------------------------------------------
	// 6. Main WHIR rounds
	// ---------------------------------------------------------------
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

		// PoW
		if err = RunPoW(api, sc, nimue, params.PowBits[r]); err != nil {
			return nil, fmt.Errorf("round %d pow: %w", r, err)
		}

		// Open previous commitment (IRS verify)
		foldingFactorPower := 1 << params.FoldingFactorArray[r]
		var numQueries int
		var stirFoldingFactor int
		if r == 0 {
			// First round: open initial commitment
			numQueries = params.InitialInDomainSamples
			stirFoldingFactor = foldingFactorPower
		} else {
			// Subsequent rounds: open previous round's commitment
			numQueries = params.RoundParametersNumOfQueries[r-1]
			stirFoldingFactor = 1 << params.FoldingFactorArray[r-1]
		}
		api.Println("IRS numQueries", numQueries)
		api.Println("IRS domainSize", domainSize)
		api.Println("IRS stirFoldingFactor", stirFoldingFactor)
		stirIndexes, err := getStirChallenges(api, nimue, numQueries, domainSize, stirFoldingFactor)
		if err != nil {
			return nil, fmt.Errorf("round %d stir: %w", r, err)
		}
		api.Println("stirIndexes", stirIndexes)
		// TODO: Re-enable Merkle/leaf verification once hints are wired up.
		// For now, skip in-domain leaf reading and Merkle proof verification.

		prevRootHash = rootHash[0]

		// Compute domain evaluation points from indices
		numBits := bits.Len(uint(domainSize - 1))
		mainRoundData.StirChallengesPoints[r] = make([]frontend.Variable, len(stirIndexes))
		for index, idx := range stirIndexes {
			mainRoundData.StirChallengesPoints[r][index] = exponentVarCircuit(api, expDomainGenerator, idx, numBits)
		}

		// Constraint values = OOD values + in-domain zero placeholders.
		// The in-domain values are zeroed until Merkle/leaf verification is enabled,
		// but the count must match the native verifier so that the geometric
		// challenge squeeze produces the same transcript state.
		numInDomainQueries := len(stirIndexes)
		constraintValues := make([]frontend.Variable, 0, len(roundOODAnswers)+numInDomainQueries)
		constraintValues = append(constraintValues, roundOODAnswers...)
		for range numInDomainQueries {
			constraintValues = append(constraintValues, frontend.Variable(0))
		}

		// Combination randomness
		roundCombRlcCoeffs, err := nimueGeometricChallenge(api, nimue, len(constraintValues))
		if err != nil {
			return nil, fmt.Errorf("round %d comb: %w", r, err)
		}
		mainRoundData.CombinationRandomness[r] = roundCombRlcCoeffs

		// Update theSum
		constraintDot := utilities.DotProduct(api, roundCombRlcCoeffs, constraintValues)
		theSum = api.Add(theSum, constraintDot)

		// Round sumcheck
		var roundFoldingRandomness []frontend.Variable
		roundFoldingRandomness, theSum, err = nimueWhirSumcheckRounds(api, nimue, theSum, params.FoldingFactorArray[r+1])
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

	// ---------------------------------------------------------------
	// 7. Final polynomial
	// ---------------------------------------------------------------
	finalVector := make([]frontend.Variable, 1<<params.FinalSumcheckRounds)
	if err = nimue.FillNextScalars(finalVector); err != nil {
		return nil, fmt.Errorf("final vector: %w", err)
	}

	// Final PoW
	if err = RunPoW(api, sc, nimue, params.FinalPowBits); err != nil {
		return nil, fmt.Errorf("final pow: %w", err)
	}

	// ---------------------------------------------------------------
	// 8. Final STIR challenges and opening
	// ---------------------------------------------------------------
	lastFoldingFactor := params.FoldingFactorArray[len(params.FoldingFactorArray)-1]
	finalIndexes, err := getStirChallenges(api, nimue, params.FinalQueries, domainSize, 1<<lastFoldingFactor)
	if err != nil {
		return nil, fmt.Errorf("final stir: %w", err)
	}

	numBits := bits.Len(uint(domainSize - 1))
	finalRandomnessPoints := make([]frontend.Variable, len(finalIndexes))
	for i, idx := range finalIndexes {
		finalRandomnessPoints[i] = exponentVarCircuit(api, expDomainGenerator, idx, numBits)
	}

	// TODO: Re-enable final round leaf/Merkle verification once hints are wired up.
	_ = prevRootHash
	_ = finalRandomnessPoints
	_ = finalVector

	// ---------------------------------------------------------------
	// 9. Final sumcheck
	// ---------------------------------------------------------------
	finalSumcheckRandomness, theSum, err := nimueWhirSumcheckRounds(api, nimue, theSum, params.FinalSumcheckRounds)
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
	// For now, skip the weight evaluation and final sumcheck equation check.
	_ = initialSumcheckData
	_ = mainRoundData
	_ = initialFormRlcCoeffs
	_ = numLinearForms
	_ = finalSumcheckRandomness

	return totalFoldingRandomness, nil
}

// ---------------------------------------------------------------------------
// ZKWhirVerifyNimue is the circuit-level ZK-WHIR verification wrapper.
// Mirrors nativeZKWhirVerify but uses gnark constraints.
// ---------------------------------------------------------------------------

func ZKWhirVerifyNimue(
	api frontend.API,
	sc *skyscraper.Skyscraper,
	nimue gnarkNimue.Nimue,
	blindedCommitment ParsedCommitmentNimue,
	blindingCommitment ParsedCommitmentNimue,
	blindedParams WHIRParams,
	blindingParams WHIRParams,
	evaluations []frontend.Variable, // claimed linear form evaluations [az, bz, cz] or [pub, az, bz, cz]
	weightsLen int, // 4 (no public) or 5 (with public)
	numPolynomials int, // typically 1
	// hr *NimueHintReader,
) error {
	numWitnessVariables := blindedParams.MVParamsNumberOfVariables
	interleavingDepth := 1 << blindedParams.FoldingFactorArray[0]

	// ---------------------------------------------------------------
	// 1. blinding_challenge
	// ---------------------------------------------------------------
	blindingChallenge := make([]frontend.Variable, 1)
	if err := nimue.FillChallengeScalars(blindingChallenge); err != nil {
		return fmt.Errorf("blinding_challenge: %w", err)
	}
	api.Println("blinding_challenge", blindingChallenge[0])

	// ---------------------------------------------------------------
	// 2. w_folded_blinding_evals
	// ---------------------------------------------------------------
	numWFoldedEvals := weightsLen * numPolynomials * (numWitnessVariables + 1)
	wFoldedBlindingEvals := make([]frontend.Variable, numWFoldedEvals)
	if err := nimue.FillNextScalars(wFoldedBlindingEvals); err != nil {
		return fmt.Errorf("w_folded_blinding_evals: %w", err)
	}
	api.Println("w_folded_blinding_evals", wFoldedBlindingEvals)
	// ---------------------------------------------------------------
	// 3. masking_challenge
	// ---------------------------------------------------------------
	maskingChallenge := make([]frontend.Variable, 1)
	if err := nimue.FillChallengeScalars(maskingChallenge); err != nil {
		return fmt.Errorf("masking_challenge: %w", err)
	}
	api.Println("masking_challenge", maskingChallenge[0])

	// ---------------------------------------------------------------
	// 4. initial_committer.verify() (IRS commit in-domain verification)
	// ---------------------------------------------------------------
	numInitialQueries := blindedParams.InitialInDomainSamples
	initialStirIndexes, err := getStirChallenges(api, nimue, numInitialQueries, blindedParams.DomainSize, interleavingDepth)
	if err != nil {
		return fmt.Errorf("initial_committer stir: %w", err)
	}
	api.Println("initial_committer stir", initialStirIndexes)

	// TODO: Re-enable once hint infrastructure is wired up.
	// Read submatrix from hints
	// _ = hr.ReadVec(numInitialQueries * interleavingDepth * blindedParams.BatchSize)

	// Verify Merkle paths for initial commitment
	// foldedDomainSize := blindedParams.DomainSize / interleavingDepth
	// treeHeight := bits.Len(uint(foldedDomainSize)) - 1
	// for range numInitialQueries {
	// 	for range treeHeight {
	// 		_ = hr.ReadHash()
	// 	}
	// }
	// _ = initialStirIndexes

	// h_gammas count
	hGammasCount := numInitialQueries * interleavingDepth
	api.Println("h_gammas count", hGammasCount)

	// ---------------------------------------------------------------
	// 5. tau1, tau2
	// ---------------------------------------------------------------
	tau1 := make([]frontend.Variable, 1)
	if err := nimue.FillChallengeScalars(tau1); err != nil {
		return fmt.Errorf("tau1: %w", err)
	}
	tau2 := make([]frontend.Variable, 1)
	if err := nimue.FillChallengeScalars(tau2); err != nil {
		return fmt.Errorf("tau2: %w", err)
	}
	api.Println("tau1", tau1[0])
	api.Println("tau2", tau2[0])

	// ---------------------------------------------------------------
	// 6. Per-gamma evaluations
	// ---------------------------------------------------------------
	evalsPerPoly := 1 + numWitnessVariables
	perGammaEvals := make([][][]frontend.Variable, hGammasCount)
	for g := range hGammasCount {
		perGammaEvals[g] = make([][]frontend.Variable, numPolynomials)
		for p := range numPolynomials {
			vals := make([]frontend.Variable, evalsPerPoly)
			if err := nimue.FillNextScalars(vals); err != nil {
				return fmt.Errorf("gamma %d poly %d: %w", g, p, err)
			}
			perGammaEvals[g][p] = vals
		}
	}
	// ---------------------------------------------------------------
	// 7. combined_claims, batched_h_claims
	// ---------------------------------------------------------------
	combinedClaims := make([]frontend.Variable, numPolynomials)
	if err := nimue.FillNextScalars(combinedClaims); err != nil {
		return fmt.Errorf("combined_claims: %w", err)
	}
	batchedHClaims := make([]frontend.Variable, numPolynomials)
	if err := nimue.FillNextScalars(batchedHClaims); err != nil {
		return fmt.Errorf("batched_h_claims: %w", err)
	}
	api.Println("combined_claims", combinedClaims)
	api.Println("batched_h_claims", batchedHClaims)

	// ---------------------------------------------------------------
	// 8. Blinded commitment WHIR verify
	// ---------------------------------------------------------------
	blindedWhirCommitment := toWhirCommitment(blindedCommitment)
	blindedWhirStatements := toWhirStatements(evaluations)
	blindedWhirParams := toWhirParams(blindedParams)

	blindedResult, err := whir.VerifyWhir(api, sc, nimue, blindedWhirCommitment, blindedWhirStatements, blindedWhirParams, nil)
	if err != nil {
		return fmt.Errorf("blinded WHIR verify: %w", err)
	}
	_ = blindedResult // FinalClaim verified by caller via R1CS matrix evaluation

	// ---------------------------------------------------------------
	// 9. Blinding commitment WHIR verify
	// ---------------------------------------------------------------
	// Accumulate m_claims and g_hat_claims using tau2 powers
	mClaims := make([]frontend.Variable, numPolynomials)
	gHatClaims := make([][]frontend.Variable, numPolynomials)
	for p := range numPolynomials {
		mClaims[p] = frontend.Variable(0)
		gHatClaims[p] = make([]frontend.Variable, numWitnessVariables)
		for j := range numWitnessVariables {
			gHatClaims[p][j] = frontend.Variable(0)
		}
	}

	tau2Power := frontend.Variable(1)
	for g := range hGammasCount {
		for p := range numPolynomials {
			evals := perGammaEvals[g][p]
			mClaims[p] = api.Add(mClaims[p], api.Mul(tau2Power, evals[0]))
			for j := range numWitnessVariables {
				gHatClaims[p][j] = api.Add(gHatClaims[p][j], api.Mul(tau2Power, evals[j+1]))
			}
		}
		tau2Power = api.Mul(tau2Power, tau2[0])
	}

	// Build subproof_claims: [m_0, g_hat_0..., m_1, g_hat_1..., ...]
	var subproofClaims []frontend.Variable
	for p := range numPolynomials {
		subproofClaims = append(subproofClaims, mClaims[p])
		subproofClaims = append(subproofClaims, gHatClaims[p]...)
	}

	// all_expected_blinding_claims = subproof_claims ++ w_folded_blinding_evals
	blindingEvaluations := append(subproofClaims, wFoldedBlindingEvals...)

	blindingWhirCommitment := toWhirCommitment(blindingCommitment)
	blindingWhirStatements := toWhirStatements(blindingEvaluations)
	blindingWhirParams := toWhirParams(blindingParams)

	blindingResult, err := whir.VerifyWhir(api, sc, nimue, blindingWhirCommitment, blindingWhirStatements, blindingWhirParams, nil)
	if err != nil {
		return fmt.Errorf("blinding WHIR verify: %w", err)
	}
	_ = blindingResult // FinalClaim verified by caller via R1CS matrix evaluation

	return nil
}

// ---------------------------------------------------------------------------
// Type conversion helpers for calling whir.VerifyWhir from the circuit package.
// ---------------------------------------------------------------------------

func toWhirCommitment(c ParsedCommitmentNimue) whir.ParsedCommitment {
	return whir.ParsedCommitment{
		Root:       c.Root,
		OodPoints:  c.OodPoints,
		OodAnswers: c.OodAnswers,
	}
}

// toWhirStatements converts a flat slice of evaluation values into
// whir.Statement objects (one per evaluation, batchSize=1).
func toWhirStatements(evaluations []frontend.Variable) []whir.Statement {
	statements := make([]whir.Statement, len(evaluations))
	for i, eval := range evaluations {
		statements[i] = whir.Statement{
			Constraints: []whir.MLConstraint{{Evaluation: eval}},
			NVars:       0,
		}
	}
	return statements
}

func toWhirParams(p WHIRParams) whir.WHIRParams {
	return whir.WHIRParams{
		ParamNRounds:                         p.ParamNRounds,
		FoldingFactorArray:                   p.FoldingFactorArray,
		RoundParametersOODSamples:            p.RoundParametersOODSamples,
		RoundParametersNumOfQueries:          p.RoundParametersNumOfQueries,
		PowBits:                              p.PowBits,
		FinalQueries:                         p.FinalQueries,
		FinalPowBits:                         p.FinalPowBits,
		FinalFoldingPowBits:                  p.FinalFoldingPowBits,
		StartingDomainBackingDomainGenerator: p.StartingDomainBackingDomainGenerator,
		DomainSize:                           p.DomainSize,
		CommittmentOODSamples:                p.CommittmentOODSamples,
		FinalSumcheckRounds:                  p.FinalSumcheckRounds,
		MVParamsNumberOfVariables:            p.MVParamsNumberOfVariables,
		BatchSize:                            p.BatchSize,
		InitialInDomainSamples:               p.InitialInDomainSamples,
	}
}

// ---------------------------------------------------------------------------
// calculateEqCircuit computes eq(a, b) = Π_i (a_i*b_i + (1-a_i)*(1-b_i))
// ---------------------------------------------------------------------------

func calculateEqCircuit(api frontend.API, a, b []frontend.Variable) frontend.Variable {
	result := frontend.Variable(1)
	for i := range a {
		ab := api.Mul(a[i], b[i])
		oneMinusA := api.Sub(frontend.Variable(1), a[i])
		oneMinusB := api.Sub(frontend.Variable(1), b[i])
		prod := api.Mul(oneMinusA, oneMinusB)
		term := api.Add(ab, prod)
		result = api.Mul(result, term)
	}
	return result
}

// ---------------------------------------------------------------------------
// expandPowersCircuit computes [1, alpha[0]*alpha[1]*..., alpha[0], ...] etc.
// Mirrors Rust expand_powers::<N> for the blinding covector weights.
// For N=4: returns [1, α₁, α₁α₂, α₁α₂α₃] where α = alpha.
// ---------------------------------------------------------------------------

func expandPowersCircuit(api frontend.API, alpha []frontend.Variable) [4]frontend.Variable {
	var result [4]frontend.Variable
	result[0] = frontend.Variable(1)
	acc := frontend.Variable(1)
	for i := 0; i < 3 && i < len(alpha); i++ {
		acc = api.Mul(acc, alpha[i])
		result[i+1] = acc
	}
	return result
}

// Dummy hint function references to satisfy HintReader.
// The actual hint functions are registered by the caller.
var _ solver.Hint = func(_ *big.Int, _ []*big.Int, _ []*big.Int) error { return nil }
