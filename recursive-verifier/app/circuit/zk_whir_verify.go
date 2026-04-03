package circuit

import (
	"fmt"

	"reilabs/whir-verifier-circuit/app/whir"

	"github.com/consensys/gnark/frontend"
	gnarkNimue "github.com/reilabs/gnark-nimue"
	skyscraper "github.com/reilabs/gnark-skyscraper"
)

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
// ZKWhirVerifyNimue is the circuit-level ZK-WHIR verification wrapper.
// Mirrors nativeZKWhirVerify but uses gnark constraints.
// ---------------------------------------------------------------------------

// CommitmentMode controls which columns of the R1CS matrices contribute to
// weight MLE evaluations in the FinalClaim checks.
type CommitmentMode int

const (
	// SingleCommitment uses all columns (single-commitment path).
	SingleCommitment CommitmentMode = iota
	// DualCommitment1 uses only columns < W1Size and includes public + blinding weights.
	DualCommitment1
	// DualCommitment2 uses only columns >= W1Size (shifted by W1Size). No public or blinding weights.
	DualCommitment2
)

// R1CSWeightParams bundles the circuit data needed to compute weight MLE
// evaluations for both the blinded and blinding FinalClaim checks.
type R1CSWeightParams struct {
	Circuit                *Circuit
	Alpha                  []frontend.Variable
	PublicWeightsChallenge frontend.Variable
	HasPublicInputs        bool
	Mode                   CommitmentMode
}

func ZKWhirVerify(
	api frontend.API,
	sc *skyscraper.Skyscraper,
	nimue gnarkNimue.Nimue,
	blindedCommitment ParsedCommitmentNimue,
	blindingCommitment ParsedCommitmentNimue,
	blindedParams WHIRParams,
	blindingParams WHIRParams,
	evaluations []frontend.Variable, // claimed linear form evaluations [pub?, az, bz, cz, blinding_eval]
	weightsLen int, // 4 (no public) or 5 (with public)
	numPolynomials int,
	blindedMerkleData *whir.WhirMerkleData,
	blindingMerkleData *whir.WhirMerkleData,
	r1csWeights R1CSWeightParams,
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
	// 7a. Verify batched_h_claims (Rust: verify!(batched_h_claims == expected_batched_h_claims))
	//     Compute gamma points from query indices and verify h-value accumulation.
	// ---------------------------------------------------------------

	// Compute gamma values: for each query index i, for k = 0..interleavingDepth-1:
	//   gamma_{i,k} = omega_full^(index_i) * zeta^k
	numBitsIdx := 0
	for v := blindedParams.DomainSize / interleavingDepth; v > 1; v >>= 1 {
		numBitsIdx++
	}
	// Precompute zeta powers: [1, zeta, zeta^2, ..., zeta^(interleavingDepth-1)]
	zetaPowers := make([]frontend.Variable, interleavingDepth)
	zetaPowers[0] = frontend.Variable(1)
	for k := 1; k < interleavingDepth; k++ {
		zetaPowers[k] = api.Mul(zetaPowers[k-1], blindedParams.Zeta)
	}

	gammas := make([]frontend.Variable, hGammasCount)
	for qi := range numInitialQueries {
		// coset_offset = omega_full^(initialStirIndexes[qi])
		cosetOffset := whir.ExponentVar(api, blindedParams.OmegaFull, initialStirIndexes[qi], numBitsIdx)
		for k := range interleavingDepth {
			gammas[qi*interleavingDepth+k] = api.Mul(cosetOffset, zetaPowers[k])
		}
	}

	// Compute expected_batched_h_claims from per-gamma evaluations.
	// Mirrors Rust whir_zk/verifier.rs lines 95-113.
	expectedBatchedHClaims := make([]frontend.Variable, numPolynomials)
	for p := range numPolynomials {
		expectedBatchedHClaims[p] = frontend.Variable(0)
	}
	tau2PowerH := frontend.Variable(1)
	for g := range hGammasCount {
		gamma := gammas[g]
		for p := range numPolynomials {
			evals := perGammaEvals[g][p]
			mEval := evals[0]
			hValue := mEval
			blindingPower := blindingChallenge[0]
			gammaPower := gamma
			for j := range numWitnessVariables {
				gHatEval := evals[j+1]
				hValue = api.Add(hValue, api.Mul(api.Mul(blindingPower, gammaPower), gHatEval))
				blindingPower = api.Mul(blindingPower, blindingChallenge[0])
				gammaPower = api.Mul(gammaPower, gammaPower)
			}
			expectedBatchedHClaims[p] = api.Add(expectedBatchedHClaims[p], api.Mul(tau2PowerH, hValue))
		}
		tau2PowerH = api.Mul(tau2PowerH, tau2[0])
	}
	for p := range numPolynomials {
		api.AssertIsEqual(batchedHClaims[p], expectedBatchedHClaims[p])
	}

	// ---------------------------------------------------------------
	// 8. Blinded commitment WHIR verify
	//    Mirrors Rust whir_zk/verifier.rs lines 118-125:
	//    modified_evaluations[i] = evaluations[i] + m_evals[i]
	//    where m_evals[i] is the first element of each (μ+1)-sized block
	//    in wFoldedBlindingEvals.
	// ---------------------------------------------------------------
	blockSize := numWitnessVariables + 1
	modifiedEvaluations := make([]frontend.Variable, len(evaluations))
	for i, eval := range evaluations {
		mEval := wFoldedBlindingEvals[i*blockSize] // first element of each block
		modifiedEvaluations[i] = api.Add(eval, mEval)
	}
	blindedWhirCommitment := toWhirCommitment(blindedCommitment)
	blindedWhirStatements := toWhirStatements(modifiedEvaluations, blindedParams.BatchSize)
	blindedWhirParams := blindedParams

	blindedResult, err := whir.VerifyWhir(api, sc, nimue, blindedWhirCommitment, blindedWhirStatements, blindedWhirParams, blindedMerkleData)
	if err != nil {
		return fmt.Errorf("blinded WHIR verify: %w", err)
	}

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

	// ---------------------------------------------------------------
	// 9a. Verify combined_claims (Rust: verify!(combined_claims == expected_combined_claims))
	//     combined_claims[p] = m_claims[p] + 2 * tau1 * univariate_evaluate(g_hat_claims[p], tau1)
	// ---------------------------------------------------------------
	for p := range numPolynomials {
		// Horner evaluation of g_hat_claims[p] at tau1
		gHatEval := frontend.Variable(0)
		for j := len(gHatClaims[p]) - 1; j >= 0; j-- {
			gHatEval = api.Add(gHatClaims[p][j], api.Mul(gHatEval, tau1[0]))
		}
		// expected = m_claims[p] + 2 * tau1 * gHatEval
		expectedCombined := api.Add(mClaims[p], api.Mul(frontend.Variable(2), api.Mul(tau1[0], gHatEval)))
		api.AssertIsEqual(combinedClaims[p], expectedCombined)
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
	blindingWhirStatements := toWhirStatements(blindingEvaluations, blindingParams.BatchSize)
	blindingWhirParams := blindingParams

	blindingResult, err := whir.VerifyWhir(api, sc, nimue, blindingWhirCommitment, blindingWhirStatements, blindingWhirParams, blindingMerkleData)
	if err != nil {
		return fmt.Errorf("blinding WHIR verify: %w", err)
	}

	// ---------------------------------------------------------------
	// 10. Blinded FinalClaim: verify WHIR-committed polynomial matches
	//     R1CS weight linear forms.
	// ---------------------------------------------------------------
	{
		w := r1csWeights
		fc := blindedResult.FinalClaim
		foldingRandomness := fc.EvaluationPoint

		var weightMLEs []frontend.Variable
		switch w.Mode {
		case SingleCommitment:
			// All columns, public + blinding weights.
			matrixExtensionEvals := evaluateR1CSMatrixExtension(api, w.Circuit, w.Alpha, foldingRandomness)
			if w.HasPublicInputs {
				weightMLEs = append(weightMLEs, geometricTill(api, w.PublicWeightsChallenge, len(w.Circuit.PublicInputs.Values), foldingRandomness))
			}
			weightMLEs = append(weightMLEs, matrixExtensionEvals[0], matrixExtensionEvals[1], matrixExtensionEvals[2])
			weightMLEs = append(weightMLEs, blindingCovectorMLE(api, w.Alpha, w.Circuit.W1Size, foldingRandomness))
		case DualCommitment1:
			// Columns < W1Size only, with public + blinding weights.
			matrixEvals1, _ := evaluateR1CSMatrixExtensionSplit(api, w.Circuit, w.Alpha, foldingRandomness, nil, w.Circuit.W1Size)
			if w.HasPublicInputs {
				weightMLEs = append(weightMLEs, geometricTill(api, w.PublicWeightsChallenge, len(w.Circuit.PublicInputs.Values), foldingRandomness))
			}
			weightMLEs = append(weightMLEs, matrixEvals1[0], matrixEvals1[1], matrixEvals1[2])
			weightMLEs = append(weightMLEs, blindingCovectorMLE(api, w.Alpha, w.Circuit.W1Size, foldingRandomness))
		case DualCommitment2:
			// Columns >= W1Size only, no public, no blinding.
			_, matrixEvals2 := evaluateR1CSMatrixExtensionSplit(api, w.Circuit, w.Alpha, nil, foldingRandomness, w.Circuit.W1Size)
			weightMLEs = append(weightMLEs, matrixEvals2[0], matrixEvals2[1], matrixEvals2[2])
		}
		fc.VerifyClaim(api, weightMLEs)
	}

	// ---------------------------------------------------------------
	// 11. Blinding FinalClaim: verify blinding polynomial matches
	//     beq_weights and folded R1CS weights.
	// ---------------------------------------------------------------
	{
		w := r1csWeights
		fc := blindingResult.FinalClaim
		evalPoint := fc.EvaluationPoint
		numBlindingVars := blindingParams.MVParamsNumberOfVariables - 1
		maskSize := 1 << (numBlindingVars + 1)

		beqMLE := batchedBeqMLE(api, gammas, maskingChallenge[0], tau2[0], numBlindingVars, evalPoint)
		weightMLEs := []frontend.Variable{beqMLE}

		switch w.Mode {
		case SingleCommitment:
			foldedMatrixEvals := evaluateFoldedR1CSMatrixExtension(api, w.Circuit, w.Alpha, evalPoint, maskSize)
			if w.HasPublicInputs {
				weightMLEs = append(weightMLEs, foldedGeometricTill(api, w.PublicWeightsChallenge, len(w.Circuit.PublicInputs.Values), evalPoint, maskSize))
			}
			weightMLEs = append(weightMLEs, foldedMatrixEvals[0], foldedMatrixEvals[1], foldedMatrixEvals[2])
			weightMLEs = append(weightMLEs, foldedBlindingCovectorMLE(api, w.Alpha, w.Circuit.W1Size, evalPoint, maskSize))
		case DualCommitment1:
			foldedEvals1, _ := evaluateFoldedR1CSMatrixExtensionSplit(api, w.Circuit, w.Alpha, evalPoint, nil, maskSize, w.Circuit.W1Size)
			if w.HasPublicInputs {
				weightMLEs = append(weightMLEs, foldedGeometricTill(api, w.PublicWeightsChallenge, len(w.Circuit.PublicInputs.Values), evalPoint, maskSize))
			}
			weightMLEs = append(weightMLEs, foldedEvals1[0], foldedEvals1[1], foldedEvals1[2])
			weightMLEs = append(weightMLEs, foldedBlindingCovectorMLE(api, w.Alpha, w.Circuit.W1Size, evalPoint, maskSize))
		case DualCommitment2:
			_, foldedEvals2 := evaluateFoldedR1CSMatrixExtensionSplit(api, w.Circuit, w.Alpha, nil, evalPoint, maskSize, w.Circuit.W1Size)
			weightMLEs = append(weightMLEs, foldedEvals2[0], foldedEvals2[1], foldedEvals2[2])
		}
		fc.VerifyClaim(api, weightMLEs)
	}

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
// whir.Statement objects, grouping every numVectors evaluations into a
// single statement with that many constraints. When numVectors=1 each
// evaluation becomes its own statement (the common case for the blinded WHIR).
func toWhirStatements(evaluations []frontend.Variable, numVectors int) []whir.Statement {
	numStatements := len(evaluations) / numVectors
	statements := make([]whir.Statement, numStatements)
	for i := range numStatements {
		constraints := make([]whir.MLConstraint, numVectors)
		for j := range numVectors {
			constraints[j] = whir.MLConstraint{Evaluation: evaluations[i*numVectors+j]}
		}
		statements[i] = whir.Statement{Constraints: constraints, NVars: 0}
	}
	return statements
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

// batchedBeqMLE computes the MLE of the batched beq_weights at evalPoint.
//
// beq_weights = Σ_g tau2^g * beq((pow(gamma_g), -maskingChallenge), ·)
//
// The MLE of a covector c at point p equals c(p) = Σ_j c[j] * L_j(p).
// Since beq is itself multilinear, its MLE at p is just beq(target, p).
// So: beq_mle(p) = Σ_g tau2^g * beq((pow(gamma_g), -maskingChallenge), p)
//
// where beq(a, b) = Π_i (a_i*b_i + (1-a_i)*(1-b_i)) over ell+1 variables:
//   - variables 0..ell-1: squaring ladder (gamma, gamma^2, gamma^4, ...)
//   - variable ell: -maskingChallenge
func batchedBeqMLE(
	api frontend.API,
	gammas []frontend.Variable,
	maskingChallenge frontend.Variable,
	tau2 frontend.Variable,
	numBlindingVars int,
	evalPoint []frontend.Variable, // ell+1 variables
) frontend.Variable {
	negRho := api.Neg(maskingChallenge)

	result := frontend.Variable(0)
	tau2Power := frontend.Variable(1)

	for _, gamma := range gammas {
		// Compute beq((pow(gamma), -rho), evalPoint)
		beqVal := frontend.Variable(1)

		// Variables 0..ell-1: squaring ladder of gamma
		gammaPower := gamma
		for i := range numBlindingVars {
			ab := api.Mul(gammaPower, evalPoint[i])
			oneMinusA := api.Sub(frontend.Variable(1), gammaPower)
			oneMinusB := api.Sub(frontend.Variable(1), evalPoint[i])
			term := api.Add(ab, api.Mul(oneMinusA, oneMinusB))
			beqVal = api.Mul(beqVal, term)
			gammaPower = api.Mul(gammaPower, gammaPower)
		}

		// Variable ell: -maskingChallenge
		{
			ab := api.Mul(negRho, evalPoint[numBlindingVars])
			oneMinusA := api.Sub(frontend.Variable(1), negRho)
			oneMinusB := api.Sub(frontend.Variable(1), evalPoint[numBlindingVars])
			term := api.Add(ab, api.Mul(oneMinusA, oneMinusB))
			beqVal = api.Mul(beqVal, term)
		}

		result = api.Add(result, api.Mul(tau2Power, beqVal))
		tau2Power = api.Mul(tau2Power, tau2)
	}

	return result
}
