package circuit

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/bits"
	"net/http"
	"os"
	"sort"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"

	"reilabs/whir-verifier-circuit/app/common"
	"reilabs/whir-verifier-circuit/app/typeConverters"
)

func FrDecimalToHexLE(decimal string) string {
	n := new(big.Int)
	_, ok := n.SetString(decimal, 10)
	if !ok {
		return ""
	}

	be := n.Bytes() // big-endian

	// pad to 32 bytes
	buf := make([]byte, 32)
	copy(buf[32-len(be):], be)

	// convert to little-endian
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}

	return hex.EncodeToString(buf)
}

// ---------------------------------------------------------------------------
// PrepareAndVerifyCircuit: replays the spongefish Fiat-Shamir transcript
// natively to determine hint offsets, reads hints, and builds the data
// structures needed by the gnark circuit. Currently skips the actual
// circuit call (the goal is to make parameter passing functional first).
// ---------------------------------------------------------------------------

func PrepareAndVerifyCircuit(config Config, r1cs R1CS, pk *groth16.ProvingKey, vk *groth16.VerifyingKey, buildOps common.BuildOps) error {
	if len(config.ProtocolID) < 64 {
		return fmt.Errorf("protocol_id must be 64 bytes, got %d", len(config.ProtocolID))
	}
	var pid [64]byte
	copy(pid[:], config.ProtocolID[:64])

	arthur := NewNativeArthur(pid, config.SessionID, config.NargString, config.Hints)
	blindedCommitmentWhirConfig := NewWhirParams(config.BlindedCommitmentWhirConfig)
	blindingCommitmentWhirConfig := NewWhirParams(config.BlindingCommitmentWhirConfig)

	// ---------------------------------------------------------------
	// 1. parseBatchedCommitment for commitment 1 (witness)
	// ---------------------------------------------------------------
	blindedCommitmentPolyRoot, blindedCommitmentOODPoint, blindedCommitmentOODMatrix, err := nativeParseBatchedCommitment(arthur, blindedCommitmentWhirConfig)
	fmt.Println("blindedCommitmentPolyRoot", FrDecimalToHexLE(blindedCommitmentPolyRoot.String()))
	fmt.Println("blindedCommitmentOODPoint", blindedCommitmentOODPoint)
	fmt.Println("blindedCommitmentOODMatrix", blindedCommitmentOODMatrix)
	if err != nil {
		return fmt.Errorf("parse blinded commitment: %w", err)
	}
	blindedCommitment := NativeCommitmentFromParsed(blindedCommitmentOODPoint, blindedCommitmentOODMatrix)

	blindingCommitmentPolyRoot, blindingCommitmentOODPoint, blindingCommitmentOODMatrix, err := nativeParseBatchedCommitment(arthur, blindingCommitmentWhirConfig)
	fmt.Println("blindingCommitmentPolyRoot", FrDecimalToHexLE(blindingCommitmentPolyRoot.String()))
	fmt.Println("blindingCommitmentOODPoint", blindingCommitmentOODPoint)
	fmt.Println("blindingCommitmentOODMatrix", blindingCommitmentOODMatrix)
	if err != nil {
		return fmt.Errorf("parse blinding commitment: %w", err)
	}
	blindingCommitment := NativeCommitmentFromParsed(blindingCommitmentOODPoint, blindingCommitmentOODMatrix)

	fmt.Println("config.BlindedCommitmentWhirConfig", config.BlindedCommitmentWhirConfig)
	fmt.Println("config.BlindingCommitmentWhirConfig", config.BlindingCommitmentWhirConfig)

	// ---------------------------------------------------------------
	// 2. If dual mode: squeeze logup challenges, parse commitment 2
	// ---------------------------------------------------------------
	if config.NumChallenges > 0 {
		a, err := arthur.FillChallengeScalars(config.NumChallenges)
		fmt.Println("challenges", a)
		if err != nil {
			return fmt.Errorf("logup challenges: %w", err)
		}
		e, f, g, err := nativeParseBatchedCommitment(arthur, blindingCommitmentWhirConfig)
		fmt.Println("e", e)
		fmt.Println("f", f)
		fmt.Println("g", g)
		if err != nil {
			return fmt.Errorf("parse commitment 2: %w", err)
		}
	}

	// ---------------------------------------------------------------
	// 3. Spartan sumcheck: squeeze tRand, then run ZK sumcheck
	// ---------------------------------------------------------------
	// 3a. tRand (Spartan verifier randomness)
	sumcheckData, err := nativeRunSumcheckVerifier(arthur, config.LogNumConstraints)
	if err != nil {
		return fmt.Errorf("sumcheck verifier: %w", err)
	}
	fmt.Println("sumcheck data:", sumcheckData)

	// ---------------------------------------------------------------
	// 4. public_inputs_hash (prover_message) + x challenge (verifier_message)
	// ---------------------------------------------------------------
	if _, err = arthur.FillNextScalars(1); err != nil {
		return fmt.Errorf("public inputs hash: %w", err)
	}
	if _, err = arthur.FillChallengeScalars(1); err != nil {
		return fmt.Errorf("x challenge: %w", err)
	}

	// ---------------------------------------------------------------
	// 5. Read claimed evaluations from hints (prover_hint_ark)
	// ---------------------------------------------------------------
	var evals1 []Fp256
	if err = arthur.ProverHintArk(&evals1); err != nil {
		return fmt.Errorf("evals_1: %w", err)
	}
	fmt.Println("evals_1:", evals1)

	// Convert evals1 to []*big.Int for WHIR verification
	evals1BigInt := fp256SliceToBigInt(evals1)

	var evals2BigInt []*big.Int
	if config.NumChallenges > 0 {
		var evals2 []Fp256
		if err = arthur.ProverHintArk(&evals2); err != nil {
			return fmt.Errorf("evals_2: %w", err)
		}
		fmt.Println("evals_2:", evals2)
		evals2BigInt = fp256SliceToBigInt(evals2)
	}

	hasPublicInputs := !config.PublicInputs.IsEmpty()
	if hasPublicInputs {
		var publicEval Fp256
		if err = arthur.ProverHintArk(&publicEval); err != nil {
			return fmt.Errorf("public_eval: %w", err)
		}
		fmt.Println("public_eval:", publicEval)
	}

	// ---------------------------------------------------------------
	// 6. zkWHIR verify (first commitment)
	//    weightsLen: 3 (A,B,C) + optional public + 1 blinding
	//    numPolynomials: 1 (single commitment)
	// ---------------------------------------------------------------
	zkWhirParams := newZKWhirVerifyParams(1, hasPublicInputs)
	_, err = nativeZKWhirVerify(arthur, config, blindedCommitmentWhirConfig, blindingCommitmentWhirConfig, zkWhirParams, blindedCommitment, blindingCommitment, evals1BigInt)
	if err != nil {
		return fmt.Errorf("zkWHIR verify commitment 1: %w", err)
	}
	// fmt.Println("zkWHIR verify 1 complete:", zkWhirData1)

	// ---------------------------------------------------------------
	// 7. If dual mode: zkWHIR verify (second commitment)
	//    weights_2 has no public weight and no blinding weight → 3 weights
	// ---------------------------------------------------------------
	if config.NumChallenges > 0 {
		zkWhirParams2 := ZKWhirVerifyParams{NumPolynomials: 1, WeightsLen: 3}
		_, err := nativeZKWhirVerify(arthur, config, blindedCommitmentWhirConfig, blindingCommitmentWhirConfig, zkWhirParams2, blindedCommitment, blindingCommitment, evals2BigInt)
		if err != nil {
			return fmt.Errorf("zkWHIR verify commitment 2: %w", err)
		}
		// fmt.Println("zkWHIR verify 2 complete:", zkWhirData2)
	}
	// ---------------------------------------------------------------
	// 8. Remaining transcript consumed. Log status.
	// ---------------------------------------------------------------
	remainingHints := arthur.hints.Len()
	remainingTranscript := len(arthur.nargString)
	fmt.Printf("Native transcript replay complete. Remaining: %d hint bytes, %d transcript bytes\n", remainingHints, remainingTranscript)

	verifyCircuit(nil, config, Hints{}, pk, vk, ClaimedEvaluations{}, ClaimedEvaluations{}, [2]Fp256{}, R1CS{}, Interner{}, buildOps, PublicInputs{})

	return nil
}

// ---------------------------------------------------------------------------
// Native sumcheck verifier (mirrors Rust run_sumcheck_verifier)
// ---------------------------------------------------------------------------

// NativeSumcheckData holds the output of the native sumcheck verifier replay.
type NativeSumcheckData struct {
	R            []*big.Int // verifier randomness (length m0)
	Alpha        []*big.Int // folding challenges (length m0)
	BlindingEval *big.Int   // blinding polynomial evaluation
	FAtAlpha     *big.Int   // f evaluated at alpha
}

// nativeEvalCubicPoly evaluates poly[0] + x*(poly[1] + x*(poly[2] + x*poly[3])) mod p.
func nativeEvalCubicPoly(poly [4]*big.Int, point *big.Int) *big.Int {
	// Horner's method: ((poly[3]*x + poly[2])*x + poly[1])*x + poly[0]
	result := new(big.Int).Set(poly[3])
	result.Mul(result, point)
	result.Add(result, poly[2])
	result.Mul(result, point)
	result.Add(result, poly[1])
	result.Mul(result, point)
	result.Add(result, poly[0])
	result.Mod(result, bn254Modulus)
	return result
}

// nativeRunSumcheckVerifier replays the Spartan sumcheck transcript and
// verifies the sumcheck equality assertions natively.
func nativeRunSumcheckVerifier(arthur *NativeArthur, m0 int) (*NativeSumcheckData, error) {
	// r = verifier_message_vec(m0)
	r, err := arthur.FillChallengeScalars(m0)
	if err != nil {
		return nil, fmt.Errorf("r: %w", err)
	}
	fmt.Println("r:", r)

	// sum_g = prover_message()
	sumGSlice, err := arthur.FillNextScalars(1)
	if err != nil {
		return nil, fmt.Errorf("sum_g: %w", err)
	}
	sumG := sumGSlice[0]
	fmt.Println("sum_g:", sumG)

	// rho = verifier_message()
	rhoSlice, err := arthur.FillChallengeScalars(1)
	if err != nil {
		return nil, fmt.Errorf("rho: %w", err)
	}
	rho := rhoSlice[0]
	fmt.Println("rho:", rho)

	// saved_val = rho * sum_g
	savedVal := new(big.Int).Mul(rho, sumG)
	savedVal.Mod(savedVal, bn254Modulus)

	alpha := make([]*big.Int, m0)

	for i := range m0 {
		// Read 4 cubic polynomial coefficients
		coeffSlice, err := arthur.FillNextScalars(4)
		if err != nil {
			return nil, fmt.Errorf("hhat coeff round %d: %w", i, err)
		}
		var hhat [4]*big.Int
		hhat[0] = coeffSlice[0]
		hhat[1] = coeffSlice[1]
		hhat[2] = coeffSlice[2]
		hhat[3] = coeffSlice[3]

		// alpha_i = verifier_message()
		alphaSlice, err := arthur.FillChallengeScalars(1)
		if err != nil {
			return nil, fmt.Errorf("alpha round %d: %w", i, err)
		}
		alpha[i] = alphaSlice[0]

		// Sumcheck equality assertion: saved_val == hhat(0) + hhat(1)
		hhatAtZero := nativeEvalCubicPoly(hhat, big.NewInt(0))
		hhatAtOne := nativeEvalCubicPoly(hhat, big.NewInt(1))
		sum := new(big.Int).Add(hhatAtZero, hhatAtOne)
		sum.Mod(sum, bn254Modulus)
		if savedVal.Cmp(sum) != 0 {
			return nil, fmt.Errorf("sumcheck equality assertion failed at round %d: %s != %s", i, savedVal.String(), sum.String())
		}

		// saved_val = hhat(alpha_i)
		savedVal = nativeEvalCubicPoly(hhat, alpha[i])
	}
	fmt.Println("alpha:", alpha)

	// blinding_eval = prover_message()
	blindingSlice, err := arthur.FillNextScalars(1)
	if err != nil {
		return nil, fmt.Errorf("blinding_eval: %w", err)
	}
	blindingEval := blindingSlice[0]
	fmt.Println("blinding_eval:", blindingEval)

	// f_at_alpha = saved_val - rho * blinding_eval
	rhoBE := new(big.Int).Mul(rho, blindingEval)
	rhoBE.Mod(rhoBE, bn254Modulus)
	fAtAlpha := new(big.Int).Sub(savedVal, rhoBE)
	fAtAlpha.Mod(fAtAlpha, bn254Modulus)
	// Ensure non-negative result (Go's Mod can return negative for negative inputs)
	if fAtAlpha.Sign() < 0 {
		fAtAlpha.Add(fAtAlpha, bn254Modulus)
	}
	fmt.Println("f_at_alpha:", fAtAlpha)

	return &NativeSumcheckData{
		R:            r,
		Alpha:        alpha,
		BlindingEval: blindingEval,
		FAtAlpha:     fAtAlpha,
	}, nil
}

// ---------------------------------------------------------------------------
// Native zkWHIR verification transcript replay
// ---------------------------------------------------------------------------

// ZKWhirVerifyParams bundles the config values needed to replay the zkWHIR
// verify transcript. All counts refer to the Rust Config fields.
type ZKWhirVerifyParams struct {
	NumPolynomials int // commitment.f_hat.len() (typically 1)
	WeightsLen     int // number of weight linear forms (includes blinding weight)
}

// newZKWhirVerifyParams derives the transcript replay parameters from the
// Config and blinded/blinding WHIRParams. The caller only needs to supply
// numPolynomials and weightsLen which depend on the call site.
func newZKWhirVerifyParams(numPolynomials int, hasPublicInputs bool) ZKWhirVerifyParams {
	// weightsLen: 3 (A,B,C) + 1 (blinding) = 4 without public inputs
	//             3 (A,B,C) + 1 (public) + 1 (blinding) = 5 with public inputs
	// The blinding weight is the last one; it is an internal zkWHIR weight used
	// to compute numWFoldedEvals from the transcript, but its evaluation is NOT
	// in the external evaluations slice passed to NativeWhirVerify.
	weightsLen := 4
	if hasPublicInputs {
		weightsLen = 5
	}
	return ZKWhirVerifyParams{
		NumPolynomials: numPolynomials,
		WeightsLen:     weightsLen,
	}
}

// NativeZKWhirData holds the transcript values parsed by nativeZKWhirVerify.
type NativeZKWhirData struct {
	BlindingChallenge    *big.Int
	WFoldedBlindingEvals []*big.Int
	MaskingChallenge     *big.Int
	InitialQueryIndices  []int
	Tau1                 *big.Int
	Tau2                 *big.Int
	// Per-gamma, per-polynomial evaluations: [gamma_idx][poly_idx] → (m_eval, g_hat_evals...)
	PerGammaEvals  [][][]*big.Int
	CombinedClaims []*big.Int
	BatchedHClaims []*big.Int
}

// nativeIRSCommitVerify replays the initial_committer.verify() transcript
// operations: squeeze in-domain challenge indices, read submatrix hint, read
// Merkle proof hints.
func nativeIRSCommitVerify(
	arthur *NativeArthur,
	numQueries int,
	domainSize int,
	foldingFactorPower int,
) ([]int, error) {
	// in_domain_challenges: squeeze challenge bytes → query indices
	indices, err := nativeGetStirChallenges(arthur, domainSize/foldingFactorPower, numQueries, false)
	if err != nil {
		return nil, fmt.Errorf("initial in-domain challenges: %w", err)
	}
	fmt.Println("initial_committer indices:", indices)

	// prover_hint_ark: read submatrix from hints
	var submatrix []Fp256
	if err = arthur.ProverHintArk(&submatrix); err != nil {
		return nil, fmt.Errorf("initial submatrix: %w", err)
	}
	fmt.Print("nativeIRSCommitVerifyWithPoints submatrix [")
	for i, v := range submatrix {
		if i > 0 {
			fmt.Print(", ")
		}
		val := typeConverters.LimbsToBigIntMod(v.Limbs)
		fmt.Print(val.String())
	}
	fmt.Println("]")
	// matrix_commit.verify: read Merkle proof from hints
	foldedDomainSize := domainSize / foldingFactorPower
	treeHeight := bits.Len(uint(foldedDomainSize)) - 1
	dedupedIndices := make([]int, len(indices))
	copy(dedupedIndices, indices)
	sort.Ints(dedupedIndices)
	dedupedIndices = dedup(dedupedIndices)

	_, err = consumeMerkleHints(arthur, dedupedIndices, treeHeight)
	if err != nil {
		return nil, fmt.Errorf("initial merkle: %w", err)
	}

	return indices, nil
}

// nativeZKWhirVerify replays the zkWHIR Config::verify() transcript.
// It parses all transcript messages in the same order as the Rust verifier,
// calling nativeIRSCommitVerify for the initial commitment and NativeWhirVerify
// for the blinded/blinding commitment WHIR verifications.
//
// blindedCommitment and blindingCommitment are the parsed commitments from
// nativeParseBatchedCommitment, converted via NativeCommitmentFromParsed.
// evaluations are the claimed linear form evaluations from the Spartan layer.
func nativeZKWhirVerify(
	arthur *NativeArthur,
	config Config,
	blindedWhirParams WHIRParams,
	blindingWhirParams WHIRParams,
	params ZKWhirVerifyParams,
	blindedCommitment *NativeCommitment,
	blindingCommitment *NativeCommitment,
	evaluations []*big.Int,
) (*NativeZKWhirData, error) {
	data := &NativeZKWhirData{}

	// Derive parameters from WHIRParams:
	// μ = num_witness_variables = blinded commitment's initial_num_variables (NVars)
	numWitnessVariables := blindedWhirParams.MVParamsNumberOfVariables
	// interleaving_depth = 1 << initial_folding_factor = 1 << foldingFactorArray[0]
	interleavingDepth := 1 << blindedWhirParams.FoldingFactorArray[0]

	// ---------------------------------------------------------------
	// 1. blinding_challenge = verifier_message()
	// ---------------------------------------------------------------
	bc, err := arthur.FillChallengeScalars(1)
	if err != nil {
		return nil, fmt.Errorf("blinding_challenge: %w", err)
	}
	data.BlindingChallenge = bc[0]
	fmt.Println("blinding_challenge:", data.BlindingChallenge)

	// ---------------------------------------------------------------
	// 2. w_folded_blinding_evals = prover_messages_vec(num_w_folded_evals)
	//    num_w_folded_evals = weights.len() * num_polynomials * (μ + 1)
	// ---------------------------------------------------------------
	numWFoldedEvals := params.WeightsLen * params.NumPolynomials * (numWitnessVariables + 1)
	wfbe, err := arthur.FillNextScalars(numWFoldedEvals)
	if err != nil {
		return nil, fmt.Errorf("w_folded_blinding_evals: %w", err)
	}
	data.WFoldedBlindingEvals = wfbe
	fmt.Println("w_folded_blinding_evals:", wfbe)

	// ---------------------------------------------------------------
	// 3. masking_challenge = verifier_message()
	// ---------------------------------------------------------------
	mc, err := arthur.FillChallengeScalars(1)
	if err != nil {
		return nil, fmt.Errorf("masking_challenge: %w", err)
	}
	data.MaskingChallenge = mc[0]
	fmt.Println("masking_challenge:", data.MaskingChallenge)

	// ---------------------------------------------------------------
	// 4. initial_committer.verify() — IRS commit in-domain verification
	//    domainSize = blinded WHIRParams DomainSize
	//    foldingFactorPower = interleaving_depth = 1 << foldingFactor[0]
	//    numQueries = initial_in_domain_samples from config
	// ---------------------------------------------------------------

	indices, err := nativeIRSCommitVerify(
		arthur,
		blindedWhirParams.InitialInDomainSamples,
		blindedWhirParams.DomainSize,
		interleavingDepth,
	)
	if err != nil {
		return nil, fmt.Errorf("initial_committer: %w", err)
	}
	data.InitialQueryIndices = indices

	// h_gammas = all_gammas(initial_in_domain.points)
	// Each query point expands to interleavingDepth gamma points.
	hGammasCount := len(indices) * interleavingDepth
	fmt.Println("h_gammas count:", hGammasCount)

	// ---------------------------------------------------------------
	// 5. tau1 = verifier_message(), tau2 = verifier_message()
	// ---------------------------------------------------------------
	tau1Slice, err := arthur.FillChallengeScalars(1)
	if err != nil {
		return nil, fmt.Errorf("tau1: %w", err)
	}
	data.Tau1 = tau1Slice[0]
	fmt.Println("tau1:", data.Tau1)

	tau2Slice, err := arthur.FillChallengeScalars(1)
	if err != nil {
		return nil, fmt.Errorf("tau2: %w", err)
	}
	data.Tau2 = tau2Slice[0]
	fmt.Println("tau2:", data.Tau2)

	// ---------------------------------------------------------------
	// 6. Per-gamma evaluation loop
	//    For each gamma in h_gammas:
	//      For each polynomial:
	//        m_eval      = prover_message()
	//        g_hat_evals = prover_message() × num_witness_variables
	// ---------------------------------------------------------------
	evalsPerPoly := 1 + numWitnessVariables // m_eval + g_hat_evals
	data.PerGammaEvals = make([][][]*big.Int, hGammasCount)
	for g := range hGammasCount {
		data.PerGammaEvals[g] = make([][]*big.Int, params.NumPolynomials)
		for p := range params.NumPolynomials {
			vals, err := arthur.FillNextScalars(evalsPerPoly)
			if err != nil {
				return nil, fmt.Errorf("gamma %d poly %d evals: %w", g, p, err)
			}
			data.PerGammaEvals[g][p] = vals
		}
	}
	fmt.Println("per-gamma evals parsed:", hGammasCount, "gammas x", params.NumPolynomials, "polys")

	// ---------------------------------------------------------------
	// 7. combined_claims = prover_messages_vec(num_polynomials)
	//    batched_h_claims = prover_messages_vec(num_polynomials)
	// ---------------------------------------------------------------
	data.CombinedClaims, err = arthur.FillNextScalars(params.NumPolynomials)
	if err != nil {
		return nil, fmt.Errorf("combined_claims: %w", err)
	}
	fmt.Println("combined_claims:", data.CombinedClaims)

	data.BatchedHClaims, err = arthur.FillNextScalars(params.NumPolynomials)
	if err != nil {
		return nil, fmt.Errorf("batched_h_claims: %w", err)
	}
	fmt.Println("batched_h_claims:", data.BatchedHClaims)

	// ---------------------------------------------------------------
	// 8. blinded_commitment.verify() — full WHIR verification
	//    Verifies the witness polynomial commitment using NativeWhirVerify.
	// ---------------------------------------------------------------
	// numLinearForms excludes the blinding weight (last in WeightsLen) because
	// the blinding evaluation is not part of the external evaluations slice.
	blindedResult, err := NativeWhirVerify(
		arthur,
		blindedWhirParams,
		config.BlindedCommitmentWhirConfig,
		[]*NativeCommitment{blindedCommitment},
		evaluations,
		params.WeightsLen-1,
	)
	if err != nil {
		return nil, fmt.Errorf("blinded_commitment verify: %w", err)
	}
	fmt.Println("blinded WHIR FinalClaim:", blindedResult.FinalClaim)

	// ---------------------------------------------------------------
	// 9. blinding_commitment.verify() — full WHIR verification
	//    Verifies the blinding polynomial commitment using NativeWhirVerify.
	//
	//    The evaluations are all_expected_blinding_claims, which is the
	//    concatenation of:
	//      - expected_batched_blinding_subproof_claims: accumulated m_claims
	//        and g_hat_claims from the per-gamma evaluation loop, interleaved
	//        as [m_0, g_hat_0..., m_1, g_hat_1..., ...] (num_polynomials *
	//        (1 + num_witness_variables) elements)
	//      - w_folded_blinding_evals: parsed from transcript at step 2
	// ---------------------------------------------------------------

	// Accumulate m_claims[p] = Σ_g tau2^g * PerGammaEvals[g][p][0]
	// and g_hat_claims[p][j] = Σ_g tau2^g * PerGammaEvals[g][p][j+1]
	mClaims := make([]*big.Int, params.NumPolynomials)
	gHatClaims := make([][]*big.Int, params.NumPolynomials)
	for p := range params.NumPolynomials {
		mClaims[p] = new(big.Int)
		gHatClaims[p] = make([]*big.Int, numWitnessVariables)
		for j := range numWitnessVariables {
			gHatClaims[p][j] = new(big.Int)
		}
	}
	tau2Power := big.NewInt(1)
	for g := range hGammasCount {
		for p := range params.NumPolynomials {
			evals := data.PerGammaEvals[g][p]
			mClaims[p] = frAdd(mClaims[p], frMul(tau2Power, evals[0]))
			for j := range numWitnessVariables {
				gHatClaims[p][j] = frAdd(gHatClaims[p][j], frMul(tau2Power, evals[j+1]))
			}
		}
		tau2Power = frMul(tau2Power, data.Tau2)
	}

	// Build subproof_claims: [m_0, g_hat_0..., m_1, g_hat_1..., ...]
	subproofClaims := make([]*big.Int, 0, params.NumPolynomials*(1+numWitnessVariables))
	for p := range params.NumPolynomials {
		subproofClaims = append(subproofClaims, mClaims[p])
		subproofClaims = append(subproofClaims, gHatClaims[p]...)
	}

	// all_expected_blinding_claims = subproof_claims ++ w_folded_blinding_evals
	blindingEvaluations := append(subproofClaims, data.WFoldedBlindingEvals...)

	blindingResult, err := NativeWhirVerify(
		arthur,
		blindingWhirParams,
		config.BlindingCommitmentWhirConfig,
		[]*NativeCommitment{blindingCommitment},
		blindingEvaluations,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("blinding_commitment verify: %w", err)
	}
	fmt.Println("blinding WHIR FinalClaim:", blindingResult.FinalClaim)

	return data, nil
}

// ---------------------------------------------------------------------------
// Native protocol replay helpers
// ---------------------------------------------------------------------------

func nativeParseBatchedCommitment(arthur *NativeArthur, whirParams WHIRParams) (
	rootHash *big.Int,
	oodPoints []*big.Int,
	oodAnswers [][]*big.Int,
	err error,
) {
	roots, e := arthur.FillNextScalars(1)
	if e != nil {
		err = e
		return
	}
	rootHash = roots[0]

	oodSamples := whirParams.RoundParametersOODSamples[0]
	oodPts, e := arthur.FillChallengeScalars(oodSamples)
	if e != nil {
		err = e
		return
	}
	oodPoints = oodPts

	fmt.Println("whirParams.BatchSize", whirParams.BatchSize)
	oodAnswers = make([][]*big.Int, whirParams.BatchSize*oodSamples)
	for i := range whirParams.BatchSize * oodSamples {
		ans, e := arthur.FillNextScalars(1)
		if e != nil {
			err = e
			return
		}
		oodAnswers[i] = ans
	}

	return
}

// nativeRunZKSumcheck replays the ZK sumcheck transcript operations and
// the embedded hiding-spartan WHIR verify.
func nativeRunZKSumcheck(arthur *NativeArthur, config Config, whirParams WHIRParams) (ZKHint, error) {
	// Parse commitment for hiding spartan blinding polynomial
	if _, _, _, err := nativeParseBatchedCommitment(arthur, whirParams); err != nil {
		return ZKHint{}, fmt.Errorf("spartan commitment: %w", err)
	}

	// sum_g + rho
	if _, err := arthur.FillNextScalars(1); err != nil {
		return ZKHint{}, fmt.Errorf("sum_g: %w", err)
	}
	if _, err := arthur.FillChallengeScalars(1); err != nil {
		return ZKHint{}, fmt.Errorf("rho: %w", err)
	}

	// Sumcheck rounds
	for range config.LogNumConstraints {
		// 4 coefficients per round (degree-3 polynomial evaluated at 0,1,2,3)
		if _, err := arthur.FillNextScalars(4); err != nil {
			return ZKHint{}, fmt.Errorf("sumcheck coeff: %w", err)
		}
		if _, err := arthur.FillChallengeScalars(1); err != nil {
			return ZKHint{}, fmt.Errorf("folding randomness: %w", err)
		}
	}

	// Polynomial sums (blinding evals)
	if _, err := arthur.FillNextScalars(2); err != nil {
		return ZKHint{}, fmt.Errorf("polynomial sums: %w", err)
	}

	// RunZKWhir for hiding spartan
	zkHint, err := nativeWhirVerify(arthur, whirParams, config.BlindedCommitmentWhirConfig)
	if err != nil {
		return ZKHint{}, fmt.Errorf("hiding spartan whir: %w", err)
	}

	return zkHint, nil
}

// nativeWhirVerify replays the full WHIR verification protocol, consuming
// transcript messages and hints. Returns the parsed Merkle proofs as a ZKHint.
func nativeWhirVerify(arthur *NativeArthur, whirParams WHIRParams, whirConfig WHIRConfig) (ZKHint, error) {
	var allMerklePaths []FullMultiPath[KeccakDigest]
	var allStirAnswers [][][]Fp256

	domainSize := whirParams.DomainSize
	nRounds := whirParams.ParamNRounds

	// --- OOD matrix (initial commitment has CommittmentOODSamples OOD evaluations) ---
	// The initial commitment's OOD entries are already on the transcript from
	// parseBatchedCommitment. The WHIR verifier now reads cross-terms for
	// the evaluation matrix if batch_size > 1.
	// For now we skip cross-term OOD reads (single vector case).

	// --- Geometric challenges: vector_rlc_coeffs ---
	numVectors := whirParams.BatchSize
	if numVectors >= 2 {
		if x, err := arthur.FillChallengeScalars(1); err != nil {
			fmt.Println("x", x)
			return ZKHint{}, fmt.Errorf("vector_rlc: %w", err)
		}
	}

	// --- Geometric challenges: constraint_rlc_coeffs ---
	numConstraints := whirParams.CommittmentOODSamples + 0 // + len(linear_forms) handled by caller
	if numConstraints >= 2 {
		if _, err := arthur.FillChallengeScalars(1); err != nil {
			return ZKHint{}, fmt.Errorf("constraint_rlc: %w", err)
		}
	}

	// --- Initial sumcheck ---
	foldingFactor0 := whirParams.FoldingFactorArray[0]
	for range foldingFactor0 {
		// c0, c2 (quadratic sumcheck polynomial)
		if _, err := arthur.FillNextScalars(2); err != nil {
			return ZKHint{}, fmt.Errorf("initial sumcheck coeff: %w", err)
		}
		// Round PoW (if any)
		// Skipped if pow bits == 0
		// folding randomness
		if _, err := arthur.FillChallengeScalars(1); err != nil {
			return ZKHint{}, fmt.Errorf("initial folding: %w", err)
		}
	}

	// --- Main rounds ---
	for r := range nRounds {
		// receive_commitment: root hash
		if _, err := arthur.FillNextScalars(1); err != nil {
			return ZKHint{}, fmt.Errorf("round %d root: %w", r, err)
		}

		// OOD points + answers for this round
		oodSamples := whirParams.RoundParametersOODSamples[r]
		if oodSamples > 0 {
			if _, err := arthur.FillChallengeScalars(oodSamples); err != nil {
				return ZKHint{}, fmt.Errorf("round %d ood points: %w", r, err)
			}
			if _, err := arthur.FillNextScalars(oodSamples); err != nil {
				return ZKHint{}, fmt.Errorf("round %d ood answers: %w", r, err)
			}
		}

		// PoW
		if whirParams.PowBits[r] > 0 {
			if _, err := arthur.FillChallengeBytes(32); err != nil {
				return ZKHint{}, fmt.Errorf("round %d pow challenge: %w", r, err)
			}
			if _, err := arthur.FillNextBytes(8); err != nil {
				return ZKHint{}, fmt.Errorf("round %d pow nonce: %w", r, err)
			}
		}

		// Challenge indices (squeeze bytes → indices)
		foldingFactorPower := 1 << whirParams.FoldingFactorArray[r]

		// 	numInitialQueries := blindedParams.InitialInDomainSamples
		// initialStirIndexes, err := getStirChallenges(api, nimue, numInitialQueries, blindedParams.DomainSize, interleavingDepth)

		indices, err := nativeGetStirChallenges(
			arthur,
			domainSize/foldingFactorPower,
			whirParams.RoundParametersNumOfQueries[r],
			false,
		)
		fmt.Println("indices", indices)
		if err != nil {
			return ZKHint{}, fmt.Errorf("round %d stir challenges: %w", r, err)
		}

		// irs_commit.verify: submatrix + merkle hints
		// Submatrix is ark-serialized Vec<F>
		var submatrix []Fp256
		if err = arthur.ProverHintArk(&submatrix); err != nil {
			return ZKHint{}, fmt.Errorf("round %d submatrix: %w", r, err)
		}
		fmt.Println("round", r)
		fmt.Print("nativeIRSCommitVerifyWithPoints submatrix [")
		for i, v := range submatrix {
			if i > 0 {
				fmt.Print(", ")
			}
			val := typeConverters.LimbsToBigIntMod(v.Limbs)
			fmt.Print(val.String())
		}
		fmt.Println("]")
		allStirAnswers = append(allStirAnswers, [][]Fp256{submatrix})

		// Merkle tree hints
		foldedDomainSize := domainSize / foldingFactorPower
		treeHeight := bits.Len(uint(foldedDomainSize)) - 1
		dedupedIndices := make([]int, len(indices))
		copy(dedupedIndices, indices)
		sort.Ints(dedupedIndices)
		dedupedIndices = dedup(dedupedIndices)

		merklePath, err := consumeMerkleHints(arthur, dedupedIndices, treeHeight)
		if err != nil {
			return ZKHint{}, fmt.Errorf("round %d merkle: %w", r, err)
		}
		allMerklePaths = append(allMerklePaths, merklePath)

		// Geometric challenge (combination randomness)
		if _, err := arthur.FillChallengeScalars(1); err != nil {
			return ZKHint{}, fmt.Errorf("round %d comb randomness: %w", r, err)
		}

		// Sumcheck for this round
		ff := whirParams.FoldingFactorArray[r]
		if r+1 < len(whirParams.FoldingFactorArray) {
			ff = whirParams.FoldingFactorArray[r+1]
		}
		for range ff {
			if _, err := arthur.FillNextScalars(2); err != nil {
				return ZKHint{}, fmt.Errorf("round %d sumcheck coeff: %w", r, err)
			}
			if _, err := arthur.FillChallengeScalars(1); err != nil {
				return ZKHint{}, fmt.Errorf("round %d sumcheck folding: %w", r, err)
			}
		}

		domainSize /= 2
	}

	// --- Final round: receive full vector ---
	finalSize := 1 << whirParams.FinalSumcheckRounds
	if _, err := arthur.FillNextScalars(finalSize); err != nil {
		return ZKHint{}, fmt.Errorf("final vector: %w", err)
	}

	// --- Final PoW ---
	if whirParams.FinalPowBits > 0 {
		if _, err := arthur.FillChallengeBytes(32); err != nil {
			return ZKHint{}, fmt.Errorf("final pow challenge: %w", err)
		}
		if _, err := arthur.FillNextBytes(8); err != nil {
			return ZKHint{}, fmt.Errorf("final pow nonce: %w", err)
		}
	}

	// --- Final opening (irs_commit.verify for last round) ---
	finalFoldingFactorPower := 1 << whirParams.FoldingFactorArray[nRounds]
	finalIndices, err := nativeGetStirChallenges(
		arthur,
		domainSize/finalFoldingFactorPower,
		whirParams.FinalQueries,
		false,
	)
	if err != nil {
		return ZKHint{}, fmt.Errorf("final stir challenges: %w", err)
	}

	var finalSubmatrix []Fp256
	if err = arthur.ProverHintArk(&finalSubmatrix); err != nil {
		return ZKHint{}, fmt.Errorf("final submatrix: %w", err)
	}
	fmt.Println("final submatrix:", finalSubmatrix)
	allStirAnswers = append(allStirAnswers, [][]Fp256{finalSubmatrix})

	foldedDomainSize := domainSize / finalFoldingFactorPower
	treeHeight := bits.Len(uint(foldedDomainSize)) - 1
	dedupedFinal := make([]int, len(finalIndices))
	copy(dedupedFinal, finalIndices)
	sort.Ints(dedupedFinal)
	dedupedFinal = dedup(dedupedFinal)

	finalMerklePath, err := consumeMerkleHints(arthur, dedupedFinal, treeHeight)
	if err != nil {
		return ZKHint{}, fmt.Errorf("final merkle: %w", err)
	}
	allMerklePaths = append(allMerklePaths, finalMerklePath)

	// --- Deferred weight evaluations ---
	var deferred []Fp256
	if err = arthur.ProverHintArk(&deferred); err != nil {
		return ZKHint{}, fmt.Errorf("deferred: %w", err)
	}
	fmt.Println("deferred:", deferred)
	log.Printf("Read %d deferred weight evaluations", len(deferred))

	// --- Final sumcheck ---
	for range whirParams.FinalSumcheckRounds {
		if _, err := arthur.FillNextScalars(2); err != nil {
			return ZKHint{}, fmt.Errorf("final sumcheck coeff: %w", err)
		}
		if _, err := arthur.FillChallengeScalars(1); err != nil {
			return ZKHint{}, fmt.Errorf("final sumcheck folding: %w", err)
		}
	}

	// --- Final folding PoW ---
	if whirParams.FinalFoldingPowBits > 0 {
		if _, err := arthur.FillChallengeBytes(32); err != nil {
			return ZKHint{}, fmt.Errorf("final folding pow challenge: %w", err)
		}
		if _, err := arthur.FillNextBytes(8); err != nil {
			return ZKHint{}, fmt.Errorf("final folding pow nonce: %w", err)
		}
	}

	// Build ZKHint from parsed data
	zkHint := consumeWhirData(whirConfig, &allMerklePaths, &allStirAnswers)

	return zkHint, nil
}

// ---------------------------------------------------------------------------
// Key management utilities (unchanged)
// ---------------------------------------------------------------------------

func GetPkAndVkFromPath(pkPath string, vkPath string) (*groth16.ProvingKey, *groth16.VerifyingKey, error) {
	var pk *groth16.ProvingKey
	var vk *groth16.VerifyingKey
	if pkPath != "" && vkPath != "" {
		log.Printf("Loading PK/VK from %s, %s", pkPath, vkPath)
		restoredPk, restoredVk, err := keysFromFiles(pkPath, vkPath)
		if err != nil {
			log.Printf("Failed to load keys from files: %v", err)
			return nil, nil, fmt.Errorf("failed to load keys from files: %w", err)
		}
		pk = &restoredPk
		vk = &restoredVk
		log.Printf("Successfully loaded PK/VK")
	}
	return pk, vk, nil
}

func GetPkAndVkFromUrl(pkUrl string, vkUrl string) (*groth16.ProvingKey, *groth16.VerifyingKey, error) {
	var pk *groth16.ProvingKey
	var vk *groth16.VerifyingKey

	if pkUrl != "" && vkUrl != "" {
		log.Printf("Downloading PK/VK from %s, %s", pkUrl, vkUrl)
		restoredPk, restoredVk, err := keysFromUrl(pkUrl, vkUrl)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load keys from url: %w", err)
		}
		pk = &restoredPk
		vk = &restoredVk
		log.Printf("Successfully downloaded and loaded PK/VK")
	}

	return pk, vk, nil
}

func GetR1csFromUrl(r1csUrl string) ([]byte, error) {
	log.Printf("Downloading R1CS from %s", r1csUrl)
	r1csFile, err := downloadFromUrl(r1csUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to download r1cs file from url: %w", err)
	}
	log.Printf("Successfully downloaded")
	return r1csFile, nil
}

func keysFromFiles(pkPath string, vkPath string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pkFile, err := os.Open(pkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open proving key file: %w", err)
	}
	defer func() {
		if err := pkFile.Close(); err != nil {
			log.Printf("failed to close proving key file: %v", err)
		}
	}()

	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(pkFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to restore proving key: %w", err)
	}

	vkFile, err := os.Open(vkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open verifying key file: %w", err)
	}
	defer func() {
		if err := vkFile.Close(); err != nil {
			log.Printf("failed to close verifying key file: %v", err)
		}
	}()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to restore verifying key: %w", err)
	}

	return pk, vk, nil
}

func keysFromUrl(pkUrl string, vkUrl string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	vkBytes, err := downloadFromUrl(vkUrl)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to download verifying key: %w", err)
	}
	log.Printf("Downloaded VK")

	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.UnsafeReadFrom(bytes.NewReader(vkBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to deserialize verifying key: %w", err)
	}
	log.Printf("Loaded VK")

	pkBytes, err := downloadFromUrl(pkUrl)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to download proving key: %v", err)
	}
	log.Printf("Downloaded PK")

	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.UnsafeReadFrom(bytes.NewReader(pkBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to deserialize proving key: %w", err)
	}
	log.Printf("Loaded PK")

	return pk, vk, nil
}

func downloadFromUrl(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("failed to download from %s: %w", url, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Warning: failed to close response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d when downloading from %s", resp.StatusCode, url)
	}

	buffer := &bytes.Buffer{}
	_, err = io.Copy(buffer, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to copy to buffer: %w", err)
	}

	return buffer.Bytes(), nil
}
