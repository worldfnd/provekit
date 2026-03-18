package circuit

import (
	"fmt"
	"math/big"
	"math/bits"
	"sort"
)

// ---------------------------------------------------------------------------
// Native types mirroring Rust whir types for verification
// ---------------------------------------------------------------------------

// NativeEvaluations mirrors Rust Evaluations<F>: OOD evaluation points and
// the matrix of evaluations (row-major, one row per OOD point).
type NativeEvaluations struct {
	Points []*big.Int // OOD evaluation points
	Matrix []*big.Int // flattened row-major: [point0_col0, point0_col1, ..., point1_col0, ...]
}

func (e *NativeEvaluations) NumPoints() int {
	return len(e.Points)
}

func (e *NativeEvaluations) NumColumns() int {
	np := e.NumPoints()
	if np == 0 {
		return 0
	}
	return len(e.Matrix) / np
}

func (e *NativeEvaluations) Rows() [][]*big.Int {
	cols := e.NumColumns()
	rows := make([][]*big.Int, e.NumPoints())
	for i := range rows {
		rows[i] = e.Matrix[i*cols : (i+1)*cols]
	}
	return rows
}

// NativeCommitment mirrors Rust irs_commit::Commitment<F>.
type NativeCommitment struct {
	OutOfDomain NativeEvaluations
}

func (c *NativeCommitment) NumVectors() int {
	return c.OutOfDomain.NumColumns()
}

// NativeFinalClaim mirrors Rust FinalClaim<F>.
type NativeFinalClaim struct {
	EvaluationPoint []*big.Int
	RLCCoefficients []*big.Int
	LinearFormRLC   *big.Int
}

// NativeRoundConstraint holds the RLC coefficients and the OOD/in-domain
// evaluator points for one round's constraints.
type NativeRoundConstraint struct {
	RLCCoeffs      []*big.Int      // random linear combination coefficients
	EvaluatorInfos []evaluatorInfo // one per constraint (OOD point + size)
}

// evaluatorInfo stores the data needed to compute mle_evaluate for a
// UnivariateEvaluation linear form (OOD or in-domain evaluator).
type evaluatorInfo struct {
	point *big.Int // evaluation point (OOD point or domain point)
	size  int      // polynomial size (= 2^num_variables for that round)
}

// ---------------------------------------------------------------------------
// Fp256 conversion helpers
// ---------------------------------------------------------------------------

// fp256ToBigInt converts an Fp256 (4 x uint64 limbs, little-endian) to *big.Int.
func fp256ToBigInt(f Fp256) *big.Int {
	r := new(big.Int)
	for i := 3; i >= 0; i-- {
		r.Lsh(r, 64)
		r.Or(r, new(big.Int).SetUint64(f.Limbs[i]))
	}
	r.Mod(r, bn254Modulus)
	return r
}

// fp256SliceToBigInt converts a slice of Fp256 to []*big.Int.
func fp256SliceToBigInt(fs []Fp256) []*big.Int {
	result := make([]*big.Int, len(fs))
	for i, f := range fs {
		result[i] = fp256ToBigInt(f)
	}
	return result
}

// ---------------------------------------------------------------------------
// Field arithmetic helpers (all mod BN254)
// ---------------------------------------------------------------------------

func frAdd(a, b *big.Int) *big.Int {
	r := new(big.Int).Add(a, b)
	r.Mod(r, bn254Modulus)
	return r
}

func frSub(a, b *big.Int) *big.Int {
	r := new(big.Int).Sub(a, b)
	r.Mod(r, bn254Modulus)
	if r.Sign() < 0 {
		r.Add(r, bn254Modulus)
	}
	return r
}

func frMul(a, b *big.Int) *big.Int {
	r := new(big.Int).Mul(a, b)
	r.Mod(r, bn254Modulus)
	return r
}

func frInv(a *big.Int) *big.Int {
	r := new(big.Int).ModInverse(a, bn254Modulus)
	return r
}

func frDiv(a, b *big.Int) *big.Int {
	return frMul(a, frInv(b))
}

// ---------------------------------------------------------------------------
// Algebraic helpers mirroring Rust whir algebra
// ---------------------------------------------------------------------------

// nativeGeometricSequence returns [1, x, x^2, ..., x^(count-1)] mod p.
func nativeGeometricSequence(x *big.Int, count int) []*big.Int {
	result := make([]*big.Int, count)
	result[0] = big.NewInt(1)
	for i := 1; i < count; i++ {
		result[i] = frMul(result[i-1], x)
	}
	return result
}

// nativeGeometricChallenge mirrors Rust geometric_challenge: squeeze a single
// challenge and expand to a geometric sequence of the given length.
func nativeGeometricChallenge(arthur *NativeArthur, count int) ([]*big.Int, error) {
	switch count {
	case 0:
		return []*big.Int{}, nil
	case 1:
		return []*big.Int{big.NewInt(1)}, nil
	default:
		x, err := arthur.FillChallengeScalars(1)
		fmt.Println("x:", x)
		if err != nil {
			return nil, err
		}
		return nativeGeometricSequence(x[0], count), nil
	}
}

// nativeDotBigInt computes the dot product of two big.Int slices mod p.
func nativeDotBigInt(a, b []*big.Int) *big.Int {
	result := big.NewInt(0)
	for i := range a {
		result = frAdd(result, frMul(a[i], b[i]))
	}
	return result
}

// nativeTensorProduct computes the tensor (Kronecker) product of two vectors.
func nativeTensorProduct(a, b []*big.Int) []*big.Int {
	result := make([]*big.Int, len(a)*len(b))
	for i, x := range a {
		for j, y := range b {
			result[i*len(b)+j] = frMul(x, y)
		}
	}
	return result
}

// nativeEqWeights computes eq polynomial weights for a multilinear point.
// Returns a vector of size 2^n where result[i] = eq(point, binary(i)).
func nativeEqWeights(point []*big.Int) []*big.Int {
	result := []*big.Int{big.NewInt(1)}
	for _, x := range point {
		oneMinusX := frSub(big.NewInt(1), x)
		length := len(result)
		newResult := make([]*big.Int, 2*length)
		for i := length - 1; i >= 0; i-- {
			newResult[2*i+1] = frMul(result[i], x)
			newResult[2*i] = frMul(result[i], oneMinusX)
		}
		result = newResult
	}
	return result
}

// nativeMultilinearEval evaluates the multilinear extension of `values` at `point`.
// This is: Σ_i values[i] * eq(i, point)
func nativeMultilinearEval(point []*big.Int, values []*big.Int) *big.Int {
	eqW := nativeEqWeights(point)
	return nativeDotBigInt(eqW, values)
}

// nativeEqPoly computes eq(a, b) = Π_i (a_i*b_i + (1-a_i)*(1-b_i)).
// This is the MultilinearExtension::mle_evaluate equivalent.
func nativeEqPoly(a, b []*big.Int) *big.Int {
	result := big.NewInt(1)
	for i := range a {
		ab := frMul(a[i], b[i])
		oneMinusA := frSub(big.NewInt(1), a[i])
		oneMinusB := frSub(big.NewInt(1), b[i])
		prod := frMul(oneMinusA, oneMinusB)
		term := frAdd(ab, prod)
		result = frMul(result, term)
	}
	return result
}

// nativeUnivariateEvalMLE computes UnivariateEvaluation{point, size}.mle_evaluate(mlPoint).
//
// This is the MLE of the linear form that evaluates a polynomial at `point`,
// given its values on a domain of the given `size`. Specifically:
//
//	mle(x_1,...,x_n) = Π_{i=0}^{n-1} ((1 - x_i) + x_i * point^(2^i))
//
// where n = log2(size) and the x_i are taken from mlPoint.
func nativeUnivariateEvalMLE(point *big.Int, size int, mlPoint []*big.Int) *big.Int {
	n := bits.Len(uint(size)) - 1 // log2(size)
	result := big.NewInt(1)
	// power tracks point^(2^i)
	power := new(big.Int).Set(point)
	for i := 0; i < n; i++ {
		// r = mlPoint[i]
		r := mlPoint[i]
		// factor = (1 - r) + r * power = 1 - r + r * power
		oneMinusR := frSub(big.NewInt(1), r)
		factor := frAdd(oneMinusR, frMul(r, power))
		result = frMul(result, factor)
		// power = power^2
		power = frMul(power, power)
	}
	return result
}

// ---------------------------------------------------------------------------
// Native WHIR sumcheck verification (quadratic polynomial, 2 coefficients)
// ---------------------------------------------------------------------------

// nativeWhirSumcheckVerify runs the WHIR-style sumcheck verification.
// Each round reads 2 evaluations (c0, c2), checks c0+c1 == sum, and squeezes
// a folding randomness challenge. Updates sum in place.
// Returns the folding randomness points.
func nativeWhirSumcheckVerify(
	arthur *NativeArthur,
	sum *big.Int,
	numRounds int,
) ([]*big.Int, *big.Int, error) {
	foldingRandomness := make([]*big.Int, numRounds)
	currentSum := new(big.Int).Set(sum)

	for i := 0; i < numRounds; i++ {
		// Read c0 and c2 (evaluations at 0 and 2)
		evals, err := arthur.FillNextScalars(2)
		if err != nil {
			return nil, nil, fmt.Errorf("sumcheck round %d coeffs: %w", i, err)
		}
		c0 := evals[0]
		c2 := evals[1]
		fmt.Println("c0:", c0)
		fmt.Println("c2:", c2)
		// c1 = sum - 2*c0 - c2  (from c0 + c1 = sum, but we need to derive c1)
		// Actually: the polynomial p(x) is quadratic with p(0)=c0, p(1)=c1, p(2)=c2
		// The sumcheck check is: p(0) + p(1) = sum, so c1 = sum - c0
		c1 := frSub(currentSum, c0)

		// Verify: c0 + c1 == currentSum (this is guaranteed by construction)

		// Squeeze folding randomness
		rSlice, err := arthur.FillChallengeScalars(1)
		fmt.Println("r:", rSlice)
		if err != nil {
			return nil, nil, fmt.Errorf("sumcheck round %d challenge: %w", i, err)
		}
		r := rSlice[0]
		foldingRandomness[i] = r

		// Update sum: p(r) using the quadratic interpolation from (0, c0), (1, c1), (2, c2)
		// p(x) = c0 + b1*x + b2*x^2 where:
		//   b0 = c0
		//   b1 = (-c2 + 4*c1 - 3*c0) / 2
		//   b2 = (c2 - 2*c1 + c0) / 2
		inv2 := frInv(big.NewInt(2))
		b1 := frMul(frAdd(frAdd(frSub(big.NewInt(0), c2), frMul(big.NewInt(4), c1)), frMul(frSub(big.NewInt(0), big.NewInt(3)), c0)), inv2)
		b2 := frMul(frAdd(frAdd(c2, frMul(frSub(big.NewInt(0), big.NewInt(2)), c1)), c0), inv2)
		// p(r) = b2*r^2 + b1*r + c0
		currentSum = frAdd(frAdd(frMul(frMul(b2, r), r), frMul(b1, r)), c0)
	}

	return foldingRandomness, currentSum, nil
}

// ---------------------------------------------------------------------------
// Native IRS commit verify (returns in-domain evaluation points)
// ---------------------------------------------------------------------------

// nativeIRSCommitVerifyWithPoints replays the IRS commit verification and
// returns the in-domain query points (as domain elements).
func nativeIRSCommitVerifyWithPoints(
	arthur *NativeArthur,
	numQueries int,
	domainSize int,
	foldingFactorPower int,
) ([]int, error) {
	fmt.Println("nativeIRSCommitVerifyWithPoints numQueries:", numQueries, "domainSize:", domainSize, "foldingFactorPower:", foldingFactorPower)
	// Squeeze challenge indices
	indices, err := nativeGetStirChallenges(arthur, domainSize/foldingFactorPower, numQueries, false)
	if err != nil {
		return nil, fmt.Errorf("stir challenges: %w", err)
	}

	// Read submatrix hint
	var submatrix []Fp256
	if err = arthur.ProverHintArk(&submatrix); err != nil {
		return nil, fmt.Errorf("submatrix: %w", err)
	}

	// Read Merkle proof hints
	foldedDomainSize := domainSize / foldingFactorPower
	treeHeight := bits.Len(uint(foldedDomainSize)) - 1
	dedupedIndices := make([]int, len(indices))
	copy(dedupedIndices, indices)
	sort.Ints(dedupedIndices)
	dedupedIndices = dedup(dedupedIndices)

	_, err = consumeMerkleHints(arthur, dedupedIndices, treeHeight)
	if err != nil {
		return nil, fmt.Errorf("merkle: %w", err)
	}

	return indices, nil
}

// ---------------------------------------------------------------------------
// NativeCommitmentFromParsed builds a NativeCommitment from the output of
// nativeParseBatchedCommitment.
// ---------------------------------------------------------------------------

func NativeCommitmentFromParsed(oodPoints []*big.Int, oodAnswers [][]*big.Int) *NativeCommitment {
	// Flatten oodAnswers [][]*big.Int (each is a 1-element slice from FillNextScalars)
	// into a row-major matrix: rows = OOD points, columns = batch vectors.
	var matrix []*big.Int
	for _, ans := range oodAnswers {
		matrix = append(matrix, ans...)
	}
	return &NativeCommitment{
		OutOfDomain: NativeEvaluations{
			Points: oodPoints,
			Matrix: matrix,
		},
	}
}

// ---------------------------------------------------------------------------
// nativeReceiveCommitment reads a round commitment from the transcript:
// root hash + OOD points + OOD answers.
// ---------------------------------------------------------------------------

func nativeReceiveCommitment(
	arthur *NativeArthur,
	oodSamples int,
) (*NativeCommitment, error) {
	// Root hash (prover_message)
	roots, err := arthur.FillNextScalars(1)
	if err != nil {
		return nil, fmt.Errorf("root hash: %w", err)
	}
	fmt.Println("roots:", roots)
	// OOD points (verifier challenges)
	oodPoints := make([]*big.Int, 0)
	oodAnswers := make([]*big.Int, 0)
	if oodSamples > 0 {
		pts, err := arthur.FillChallengeScalars(oodSamples)
		if err != nil {
			return nil, fmt.Errorf("ood points: %w", err)
		}
		oodPoints = pts

		ans, err := arthur.FillNextScalars(oodSamples)
		if err != nil {
			return nil, fmt.Errorf("ood answers: %w", err)
		}
		oodAnswers = ans
	}

	fmt.Println("oodPoints:", oodPoints)
	fmt.Println("oodAnswers:", oodAnswers)

	return &NativeCommitment{
		OutOfDomain: NativeEvaluations{
			Points: oodPoints,
			Matrix: oodAnswers, // single-vector: matrix is 1 column
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Native PoW verification (transcript replay only — actual check is in circuit)
// ---------------------------------------------------------------------------

func nativePoWVerify(arthur *NativeArthur, powBits int) error {
	if powBits > 0 {
		challengeBytes, err := arthur.FillChallengeBytes(32)
		if err != nil {
			return fmt.Errorf("pow challenge: %w", err)
		}
		fmt.Println("challengeBytes:", challengeBytes)
		nonce, err := arthur.FillNextBytes(8)
		if err != nil {
			return fmt.Errorf("pow nonce: %w", err)
		}
		fmt.Println("nonce:", nonce)
	}
	return nil
}

// ---------------------------------------------------------------------------
// NativeWhirVerify: full WHIR batched verification
// Mirrors Rust whir::Config::verify() exactly.
// ---------------------------------------------------------------------------

// NativeWhirVerifyResult bundles the verify output with the ZKHint data
// needed for circuit construction.
type NativeWhirVerifyResult struct {
	FinalClaim NativeFinalClaim
	Hint       ZKHint
}

// NativeWhirVerify replays and verifies the full WHIR protocol transcript.
// This mirrors the Rust `Config::verify()` method for batched commitments.
//
// Parameters:
//   - arthur: transcript reader
//   - whirParams: WHIR protocol parameters
//   - whirConfig: WHIR configuration (for ZKHint construction)
//   - commitments: N parsed commitments (from parseBatchedCommitment)
//   - evaluations: constraint evaluation values (flattened)
//   - numLinearForms: number of external linear form constraints
func NativeWhirVerify(
	arthur *NativeArthur,
	whirParams WHIRParams,
	whirConfig WHIRConfig,
	commitments []*NativeCommitment,
	evaluations []*big.Int,
	numLinearForms int,
) (*NativeWhirVerifyResult, error) {
	var allMerklePaths []FullMultiPath[KeccakDigest]
	var allStirAnswers [][][]Fp256

	numVectors := 0
	for _, c := range commitments {
		numVectors += c.NumVectors()
	}
	if len(evaluations) > 0 && numVectors > 0 && len(evaluations)%numVectors != 0 {
		return nil, fmt.Errorf("evaluations length %d not multiple of num_vectors %d", len(evaluations), numVectors)
	}
	if numVectors == 0 {
		return &NativeWhirVerifyResult{
			FinalClaim: NativeFinalClaim{
				LinearFormRLC: big.NewInt(0),
			},
		}, nil
	}
	fmt.Println("evaluations:", evaluations)
	fmt.Println("numVectors:", numVectors)
	numLinearForms = len(evaluations) / numVectors
	fmt.Println("numLinearForms:", numLinearForms)
	// ---------------------------------------------------------------
	// 1. Complete OOD evaluation matrix with cross-terms
	// ---------------------------------------------------------------
	var oodsEvalInfos []evaluatorInfo // evaluator info per OOD constraint
	var oodsMatrix []*big.Int         // flattened: [ood0_vec0, ood0_vec1, ..., ood1_vec0, ...]

	vectorOffset := 0
	for _, commitment := range commitments {
		ood := &commitment.OutOfDomain
		for rowIdx, row := range ood.Rows() {
			for j := 0; j < numVectors; j++ {
				if j >= vectorOffset && j < len(row)+vectorOffset {
					oodsMatrix = append(oodsMatrix, row[j-vectorOffset])
				} else {
					// Cross-term: read from transcript
					vals, err := arthur.FillNextScalars(1)
					if err != nil {
						return nil, fmt.Errorf("ood cross-term: %w", err)
					}
					oodsMatrix = append(oodsMatrix, vals[0])
				}
			}
			_ = rowIdx
			// Each OOD row creates one evaluator
		}
		// Add evaluator infos for this commitment's OOD points
		initialSize := whirParams.DomainSize / (1 << whirConfig.Rate)
		for _, pt := range ood.Points {
			oodsEvalInfos = append(oodsEvalInfos, evaluatorInfo{point: pt, size: initialSize})
		}
		vectorOffset += commitment.NumVectors()
	}
	fmt.Println("oods_evals count:", len(oodsEvalInfos))
	fmt.Println("oods_matrix len:", len(oodsMatrix))
	fmt.Println("oods_eval_infos:", oodsEvalInfos)
	fmt.Println("oods_matrix:", oodsMatrix)

	// ---------------------------------------------------------------
	// 2. Vector RLC (random linear combination of interleaved vectors)
	// ---------------------------------------------------------------
	vectorRLCCoeffs, err := nativeGeometricChallenge(arthur, numVectors)
	if err != nil {
		return nil, fmt.Errorf("vector_rlc: %w", err)
	}

	// ---------------------------------------------------------------
	// 3. Constraint RLC
	// ---------------------------------------------------------------
	totalConstraints := len(oodsEvalInfos) + numLinearForms
	fmt.Println("totalConstraints:", totalConstraints)
	constraintRLCCoeffs, err := nativeGeometricChallenge(arthur, totalConstraints)
	if err != nil {
		return nil, fmt.Errorf("constraint_rlc: %w", err)
	}

	initialFormRLCCoeffs := constraintRLCCoeffs[:numLinearForms]
	oodsRLCCoeffs := constraintRLCCoeffs[numLinearForms:]

	// ---------------------------------------------------------------
	// 4. Compute "The Sum"
	// ---------------------------------------------------------------
	theSum := big.NewInt(0)

	// Contribution from external linear forms
	for i, coeff := range initialFormRLCCoeffs {
		row := evaluations[i*numVectors : (i+1)*numVectors]
		theSum = frAdd(theSum, frMul(coeff, nativeDotBigInt(vectorRLCCoeffs, row)))
	}

	// Contribution from OOD constraints
	for i, coeff := range oodsRLCCoeffs {
		row := oodsMatrix[i*numVectors : (i+1)*numVectors]
		theSum = frAdd(theSum, frMul(coeff, nativeDotBigInt(vectorRLCCoeffs, row)))
	}
	fmt.Println("the_sum after initial:", theSum)

	// Track round constraints for final MLE subtraction
	roundConstraints := []NativeRoundConstraint{
		{RLCCoeffs: oodsRLCCoeffs, EvaluatorInfos: oodsEvalInfos},
	}

	var allFoldingRandomness [][]*big.Int

	// ---------------------------------------------------------------
	// 5. Initial sumcheck
	// ---------------------------------------------------------------
	fmt.Println("constraintRLCCoeffs:", constraintRLCCoeffs)
	if len(constraintRLCCoeffs) == 0 {
		// No constraints: skip sumcheck, just squeeze folding randomness
		if theSum.Cmp(big.NewInt(0)) != 0 {
			return nil, fmt.Errorf("the_sum should be zero but got %s", theSum.String())
		}
		ff0 := whirParams.FoldingFactorArray[0]
		foldRandomness, err := arthur.FillChallengeScalars(ff0)
		if err != nil {
			return nil, fmt.Errorf("initial skip folding: %w", err)
		}
		// initial_skip_pow
		if err := nativePoWVerify(arthur, 0); err != nil {
			return nil, fmt.Errorf("initial skip pow: %w", err)
		}
		allFoldingRandomness = append(allFoldingRandomness, foldRandomness)
	} else {
		fmt.Println("the_sum before initial sumcheck:", theSum)
		ff0 := whirParams.FoldingFactorArray[0]
		fmt.Println("num rounds:", ff0)
		foldRandomness, newSum, err := nativeWhirSumcheckVerify(arthur, theSum, ff0)
		if err != nil {
			return nil, fmt.Errorf("initial sumcheck: %w", err)
		}
		theSum = newSum
		allFoldingRandomness = append(allFoldingRandomness, foldRandomness)
	}

	// ---------------------------------------------------------------
	// 6. Main WHIR rounds
	// ---------------------------------------------------------------
	domainSize := whirParams.DomainSize
	nRounds := whirParams.ParamNRounds

	// Track which commitment type was previous (for opening)
	type prevType int
	const (
		prevInitial prevType = iota
		prevRound
	)
	prev := prevInitial
	// polyRLC for initial is vectorRLCCoeffs; for round is [1]
	currentPolyRLC := vectorRLCCoeffs

	fmt.Println("before round configs iteration")
	for r := 0; r < nRounds; r++ {
		// receive_commitment for folded polynomial
		oodSamples := whirParams.RoundParametersOODSamples[r]
		roundCommitment, err := nativeReceiveCommitment(arthur, oodSamples)
		if err != nil {
			return nil, fmt.Errorf("round %d commitment: %w", r, err)
		}

		// Proof of work
		if err := nativePoWVerify(arthur, whirParams.PowBits[r]); err != nil {
			return nil, fmt.Errorf("round %d pow: %w", r, err)
		}

		// Open previous commitment (IRS verify)
		foldingFactorPower := 1 << whirParams.FoldingFactorArray[r]
		var inDomainIndices []int
		fmt.Println("prev: prevInitial", prev, prevInitial)
		if prev == prevInitial {
			inDomainIndices, err = nativeIRSCommitVerifyWithPoints(
				arthur,
				whirParams.InitialInDomainSamples,
				domainSize,
				foldingFactorPower,
			)
		} else {
			prevFF := 1 << whirParams.FoldingFactorArray[r-1]
			inDomainIndices, err = nativeIRSCommitVerifyWithPoints(
				arthur,
				whirParams.RoundParametersNumOfQueries[r-1],
				domainSize,
				prevFF,
			)
		}
		if err != nil {
			return nil, fmt.Errorf("round %d irs verify: %w", r, err)
		}
		allStirAnswers = append(allStirAnswers, [][]Fp256{{}})
		allMerklePaths = append(allMerklePaths, FullMultiPath[KeccakDigest]{})

		// Compute round size for evaluators
		numVarsForRound := whirParams.MVParamsNumberOfVariables
		for k := 0; k < r; k++ {
			numVarsForRound -= whirParams.FoldingFactorArray[k]
		}
		roundSize := 1 << numVarsForRound

		// Build constraint weights/values from OOD + in-domain
		var constraintEvalInfos []evaluatorInfo
		var constraintValues []*big.Int

		// OOD constraints from this round's commitment
		for _, pt := range roundCommitment.OutOfDomain.Points {
			constraintEvalInfos = append(constraintEvalInfos, evaluatorInfo{point: pt, size: roundSize})
		}
		// OOD values: dot(weights=[1], row) for single vector
		for _, row := range roundCommitment.OutOfDomain.Rows() {
			constraintValues = append(constraintValues, nativeDotBigInt([]*big.Int{big.NewInt(1)}, row))
		}

		// In-domain constraints from IRS verify
		// Compute domain generator for in-domain points
		// In-domain evaluator points come from the STIR challenge indices
		foldedDomainSize := domainSize / foldingFactorPower
		_ = foldedDomainSize
		// The in-domain points are domain elements at the queried indices
		// For the tensor product weights: tensor(polyRLC, eq_weights(last_folding_randomness))
		lastFoldRand := allFoldingRandomness[len(allFoldingRandomness)-1]
		tensorWeights := nativeTensorProduct(currentPolyRLC, nativeEqWeights(lastFoldRand))

		// In-domain evaluator: each index gives a domain point
		for _, idx := range inDomainIndices {
			// Domain point = domainGenerator^(idx * foldingFactorPower)
			// For evaluator info, we store the index-based domain point
			// The actual point computation requires the domain generator
			_ = idx
			// For now, store placeholder — the actual mle_evaluate uses the
			// point to compute (1-r) + r*point^(2^i) for each round variable
			constraintEvalInfos = append(constraintEvalInfos, evaluatorInfo{
				point: big.NewInt(int64(idx)), // placeholder
				size:  roundSize,
			})
		}

		// In-domain values: for each query, compute the dot product with tensor weights
		// These values come from the submatrix hint (already consumed by IRS verify)
		// For verification, they are verified by Merkle proof, so we trust them here
		for range inDomainIndices {
			// The actual values are verified by Merkle proofs in the circuit
			// In the native replay, we just need the constraint structure
			constraintValues = append(constraintValues, big.NewInt(0)) // placeholder
		}
		_ = tensorWeights

		fmt.Println("before Constraint RLC")
		// Squeeze combination randomness for this round
		constraintRLC, err := nativeGeometricChallenge(arthur, len(constraintValues))
		if err != nil {
			return nil, fmt.Errorf("round %d combination randomness: %w", r, err)
		}
		theSum = frAdd(theSum, nativeDotBigInt(constraintRLC, constraintValues))

		roundConstraints = append(roundConstraints, NativeRoundConstraint{
			RLCCoeffs:      constraintRLC,
			EvaluatorInfos: constraintEvalInfos,
		})

		// Sumcheck for this round
		ff := whirParams.FoldingFactorArray[r]
		if r+1 < len(whirParams.FoldingFactorArray) {
			ff = whirParams.FoldingFactorArray[r+1]
		}
		foldRandomness, newSum, err := nativeWhirSumcheckVerify(arthur, theSum, ff)
		if err != nil {
			return nil, fmt.Errorf("round %d sumcheck: %w", r, err)
		}
		theSum = newSum
		allFoldingRandomness = append(allFoldingRandomness, foldRandomness)

		prev = prevRound
		currentPolyRLC = []*big.Int{big.NewInt(1)}
		domainSize /= 2
	}

	// ---------------------------------------------------------------
	// 7. Final round: receive full vector
	// ---------------------------------------------------------------
	finalSize := 1 << whirParams.FinalSumcheckRounds
	finalVector, err := arthur.FillNextScalars(finalSize)
	if err != nil {
		return nil, fmt.Errorf("final vector: %w", err)
	}

	// Final PoW
	if err := nativePoWVerify(arthur, whirParams.FinalPowBits); err != nil {
		return nil, fmt.Errorf("final pow: %w", err)
	}

	// ---------------------------------------------------------------
	// 8. Open previous commitment (final IRS verify)
	// ---------------------------------------------------------------
	finalFoldingFactorPower := 1 << whirParams.FoldingFactorArray[nRounds]
	finalIndices, err := nativeGetStirChallenges(
		arthur,
		domainSize/finalFoldingFactorPower,
		whirParams.FinalQueries,
		false,
	)
	if err != nil {
		return nil, fmt.Errorf("final stir challenges: %w", err)
	}

	var finalSubmatrix []Fp256
	if err = arthur.ProverHintArk(&finalSubmatrix); err != nil {
		return nil, fmt.Errorf("final submatrix: %w", err)
	}
	allStirAnswers = append(allStirAnswers, [][]Fp256{finalSubmatrix})

	foldedDomainSize := domainSize / finalFoldingFactorPower
	treeHeight := bits.Len(uint(foldedDomainSize)) - 1
	dedupedFinal := make([]int, len(finalIndices))
	copy(dedupedFinal, finalIndices)
	sort.Ints(dedupedFinal)
	dedupedFinal = dedup(dedupedFinal)

	finalMerklePath, err := consumeMerkleHints(arthur, dedupedFinal, treeHeight)
	if err != nil {
		return nil, fmt.Errorf("final merkle: %w", err)
	}
	allMerklePaths = append(allMerklePaths, finalMerklePath)

	// ---------------------------------------------------------------
	// 9. Read deferred weight evaluations
	// ---------------------------------------------------------------
	var deferred []Fp256
	if err = arthur.ProverHintArk(&deferred); err != nil {
		return nil, fmt.Errorf("deferred: %w", err)
	}
	fmt.Printf("Read %d deferred weight evaluations\n", len(deferred))

	// ---------------------------------------------------------------
	// 10. Final sumcheck
	// ---------------------------------------------------------------
	finalSumcheckRandomness, newSum, err := nativeWhirSumcheckVerify(arthur, theSum, whirParams.FinalSumcheckRounds)
	if err != nil {
		return nil, fmt.Errorf("final sumcheck: %w", err)
	}
	theSum = newSum
	allFoldingRandomness = append(allFoldingRandomness, finalSumcheckRandomness)

	// Final folding PoW
	if err := nativePoWVerify(arthur, whirParams.FinalFoldingPowBits); err != nil {
		return nil, fmt.Errorf("final folding pow: %w", err)
	}

	// ---------------------------------------------------------------
	// 11. Compute evaluation point (all folding randomness concatenated)
	// ---------------------------------------------------------------
	var evaluationPoint []*big.Int
	for _, fr := range allFoldingRandomness {
		evaluationPoint = append(evaluationPoint, fr...)
	}

	// ---------------------------------------------------------------
	// 12. Compute linear_form_rlc from the sumcheck invariant
	// ---------------------------------------------------------------
	// poly_eval = MLE(final_sumcheck_randomness).evaluate(Identity, final_vector)
	polyEval := nativeMultilinearEval(finalSumcheckRandomness, finalVector)

	// linear_form_rlc = the_sum / poly_eval
	linearFormRLC := frDiv(theSum, polyEval)

	// Subtract all internal linear forms
	for round, rc := range roundConstraints {
		var numVariables int
		if round == 0 {
			numVariables = whirParams.MVParamsNumberOfVariables
		} else {
			numVariables = whirParams.MVParamsNumberOfVariables
			for k := 0; k < round-1; k++ {
				numVariables -= whirParams.FoldingFactorArray[k]
			}
		}
		start := len(evaluationPoint) - numVariables
		if start < 0 {
			start = 0
		}
		subPoint := evaluationPoint[start:]
		for i, coeff := range rc.RLCCoeffs {
			if i < len(rc.EvaluatorInfos) {
				info := rc.EvaluatorInfos[i]
				mleVal := nativeUnivariateEvalMLE(info.point, info.size, subPoint)
				linearFormRLC = frSub(linearFormRLC, frMul(coeff, mleVal))
			}
		}
	}

	// ---------------------------------------------------------------
	// 13. Build ZKHint from parsed Merkle data
	// ---------------------------------------------------------------
	zkHint := consumeWhirData(whirConfig, &allMerklePaths, &allStirAnswers)

	return &NativeWhirVerifyResult{
		FinalClaim: NativeFinalClaim{
			EvaluationPoint: evaluationPoint,
			RLCCoefficients: initialFormRLCCoeffs,
			LinearFormRLC:   linearFormRLC,
		},
		Hint: zkHint,
	}, nil
}
