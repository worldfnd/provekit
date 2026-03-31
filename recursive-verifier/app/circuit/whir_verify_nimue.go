package circuit

import (
	"fmt"
	"math/big"

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
// ZKWhirVerifyNimue is the circuit-level ZK-WHIR verification wrapper.
// Mirrors nativeZKWhirVerify but uses gnark constraints.
// ---------------------------------------------------------------------------

// ZKWhirVerifyResult holds the outputs from ZKWhirVerifyNimue needed for
// deferred evaluation checks (FinalClaim binding).
type ZKWhirVerifyResult struct {
	BlindedResult  *whir.VerifyResult
	BlindingResult *whir.VerifyResult
}

func ZKWhirVerifyNimue(
	api frontend.API,
	sc *skyscraper.Skyscraper,
	nimue gnarkNimue.Nimue,
	blindedCommitment ParsedCommitmentNimue,
	blindingCommitment ParsedCommitmentNimue,
	blindedParams WHIRParams,
	blindingParams WHIRParams,
	evaluations []frontend.Variable, // claimed linear form evaluations [pub?, az, bz, cz, blinding_eval]
	weightsLen int, // 4 (no public) or 5 (with public)
	numPolynomials int, // typically 1
	blindedMerkleData *whir.WhirMerkleData,
	blindingMerkleData *whir.WhirMerkleData,
) (*ZKWhirVerifyResult, error) {
	numWitnessVariables := blindedParams.MVParamsNumberOfVariables
	interleavingDepth := 1 << blindedParams.FoldingFactorArray[0]

	// ---------------------------------------------------------------
	// 1. blinding_challenge
	// ---------------------------------------------------------------
	blindingChallenge := make([]frontend.Variable, 1)
	if err := nimue.FillChallengeScalars(blindingChallenge); err != nil {
		return nil, fmt.Errorf("blinding_challenge: %w", err)
	}
	api.Println("blinding_challenge", blindingChallenge[0])

	// ---------------------------------------------------------------
	// 2. w_folded_blinding_evals
	// ---------------------------------------------------------------
	numWFoldedEvals := weightsLen * numPolynomials * (numWitnessVariables + 1)
	wFoldedBlindingEvals := make([]frontend.Variable, numWFoldedEvals)
	if err := nimue.FillNextScalars(wFoldedBlindingEvals); err != nil {
		return nil, fmt.Errorf("w_folded_blinding_evals: %w", err)
	}
	api.Println("w_folded_blinding_evals", wFoldedBlindingEvals)
	// ---------------------------------------------------------------
	// 3. masking_challenge
	// ---------------------------------------------------------------
	maskingChallenge := make([]frontend.Variable, 1)
	if err := nimue.FillChallengeScalars(maskingChallenge); err != nil {
		return nil, fmt.Errorf("masking_challenge: %w", err)
	}
	api.Println("masking_challenge", maskingChallenge[0])

	// ---------------------------------------------------------------
	// 4. initial_committer.verify() (IRS commit in-domain verification)
	// ---------------------------------------------------------------
	numInitialQueries := blindedParams.InitialInDomainSamples
	initialStirIndexes, err := getStirChallenges(api, nimue, numInitialQueries, blindedParams.DomainSize, interleavingDepth)
	if err != nil {
		return nil, fmt.Errorf("initial_committer stir: %w", err)
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
		return nil, fmt.Errorf("tau1: %w", err)
	}
	tau2 := make([]frontend.Variable, 1)
	if err := nimue.FillChallengeScalars(tau2); err != nil {
		return nil, fmt.Errorf("tau2: %w", err)
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
				return nil, fmt.Errorf("gamma %d poly %d: %w", g, p, err)
			}
			perGammaEvals[g][p] = vals
		}
	}
	// ---------------------------------------------------------------
	// 7. combined_claims, batched_h_claims
	// ---------------------------------------------------------------
	combinedClaims := make([]frontend.Variable, numPolynomials)
	if err := nimue.FillNextScalars(combinedClaims); err != nil {
		return nil, fmt.Errorf("combined_claims: %w", err)
	}
	batchedHClaims := make([]frontend.Variable, numPolynomials)
	if err := nimue.FillNextScalars(batchedHClaims); err != nil {
		return nil, fmt.Errorf("batched_h_claims: %w", err)
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
	//    The Go implementation passes raw evaluations to the inner WHIR
	//    verifier (matching the native NativeWhirVerify). The m_evals
	//    adjustment is not applied here because the Go WHIR verifier
	//    handles the evaluation binding differently from Rust's whir_zk.
	// ---------------------------------------------------------------
	blindedWhirCommitment := toWhirCommitment(blindedCommitment)
	blindedWhirStatements := toWhirStatements(evaluations)
	blindedWhirParams := toWhirParams(blindedParams)

	blindedResult, err := whir.VerifyWhir(api, sc, nimue, blindedWhirCommitment, blindedWhirStatements, blindedWhirParams, blindedMerkleData)
	if err != nil {
		return nil, fmt.Errorf("blinded WHIR verify: %w", err)
	}

	// NOTE: Blinded FinalClaim constraint is enforced by the caller (circuit.Define)
	// using evaluateR1CSMatrixExtension against the R1CS matrices embedded in the circuit.

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
	blindingWhirStatements := toWhirStatements(blindingEvaluations)
	blindingWhirParams := toWhirParams(blindingParams)

	blindingResult, err := whir.VerifyWhir(api, sc, nimue, blindingWhirCommitment, blindingWhirStatements, blindingWhirParams, blindingMerkleData)
	if err != nil {
		return nil, fmt.Errorf("blinding WHIR verify: %w", err)
	}

	// TODO(soundness): Blinding FinalClaim constraint (same as blinded above).
	// The blinding weights are beq_weights (batched eq from gammas) and
	// w_folded_weights (folded R1CS weights). Their MLE evaluations at the
	// blinding evaluation point must match LinearFormRLC.

	return &ZKWhirVerifyResult{
		BlindedResult:  blindedResult,
		BlindingResult: blindingResult,
	}, nil
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

// Dummy hint function references to satisfy HintReader.
// The actual hint functions are registered by the caller.
var _ solver.Hint = func(_ *big.Int, _ []*big.Int, _ []*big.Int) error { return nil }
