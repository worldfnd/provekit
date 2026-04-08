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
	"reilabs/whir-verifier-circuit/app/whir"
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

	// Compute instance = public_inputs.hash_bytes() to bind public inputs to the transcript.
	piValues := make([]*big.Int, len(config.PublicInputs.Values))
	for i, v := range config.PublicInputs.Values {
		piValues[i] = v.(*big.Int)
	}
	instance := nativePublicInputsHashBytes(piValues)

	nimue := NewNativeNimue(pid, config.SessionID, instance, config.NargString, config.Hints)
	blindedCommitmentWhirConfig := NewWhirParams(config.BlindedCommitmentWhirConfig)
	blindingCommitmentWhirConfig := NewWhirParams(config.BlindingCommitmentWhirConfig)

	_, blindedCommitmentOODPoint, blindedCommitmentOODMatrix, err := nativeParseBatchedCommitment(nimue, blindedCommitmentWhirConfig)

	if err != nil {
		return fmt.Errorf("parse blinded commitment: %w", err)
	}
	blindedCommitment := NativeCommitmentFromParsed(blindedCommitmentOODPoint, blindedCommitmentOODMatrix)

	_, blindingCommitmentOODPoint, blindingCommitmentOODMatrix, err := nativeParseBatchedCommitment(nimue, blindingCommitmentWhirConfig)

	if err != nil {
		return fmt.Errorf("parse blinding commitment: %w", err)
	}
	blindingCommitment := NativeCommitmentFromParsed(blindingCommitmentOODPoint, blindingCommitmentOODMatrix)

	if config.NumChallenges > 0 {
		_, err := nimue.FillChallengeScalars(config.NumChallenges)
		if err != nil {
			return fmt.Errorf("logup challenges: %w", err)
		}
		_, _, _, err = nativeParseBatchedCommitment(nimue, blindedCommitmentWhirConfig)
		if err != nil {
			return fmt.Errorf("parse commitment 2 blinded: %w", err)
		}
		_, _, _, err = nativeParseBatchedCommitment(nimue, blindingCommitmentWhirConfig)
		if err != nil {
			return fmt.Errorf("parse commitment 2: %w", err)
		}
	}

	// Spartan sumcheck: squeeze tRand, then run ZK sumcheck
	sumcheckData, err := nativeRunSumcheckVerifier(nimue, config.LogNumConstraints)
	if err != nil {
		return fmt.Errorf("sumcheck verifier: %w", err)
	}

	_, err = nimue.FillNextScalars(1)
	if err != nil {
		return fmt.Errorf("public inputs hash: %w", err)
	}

	_, err = nimue.FillChallengeScalars(1)
	if err != nil {
		return fmt.Errorf("x challenge: %w", err)
	}

	// Read evaluations from transcript (prover_message in Rust)
	evals1Scalars, err := nimue.FillNextScalars(3)
	if err != nil {
		return fmt.Errorf("evals_1: %w", err)
	}
	evals1BigInt := evals1Scalars

	var evals2BigInt []*big.Int
	if config.NumChallenges > 0 {
		evals2Scalars, err := nimue.FillNextScalars(3)
		if err != nil {
			return fmt.Errorf("evals_2: %w", err)
		}
		evals2BigInt = evals2Scalars
	}

	hasPublicInputs := !config.PublicInputs.IsEmpty()
	var publicEval *big.Int
	if hasPublicInputs {
		publicEvalSlice, err := nimue.FillNextScalars(1)
		if err != nil {
			return fmt.Errorf("public_eval: %w", err)
		}
		publicEval = publicEvalSlice[0]
	}

	// Challenge binding: in dual mode, read challenge_eval from transcript
	// (prover_message in Rust). This binds w2's challenge values to the transcript.
	// challenge_eval is appended to evaluations_2 and an extra weight is added.
	var challengeEval *big.Int
	if config.NumChallenges > 0 {
		ceSlice, err := nimue.FillNextScalars(1)
		if err != nil {
			return fmt.Errorf("challenge_eval: %w", err)
		}
		challengeEval = ceSlice[0]
	}

	// Build the full evaluations vector matching Rust whir_r1cs.rs:
	//   [public_eval?, Az, Bz, Cz, blinding_eval]
	// The blinding_eval comes from the Spartan sumcheck verifier output.
	blindingEval := sumcheckData.BlindingEval
	var fullEvals1 []*big.Int
	if hasPublicInputs {
		fullEvals1 = append([]*big.Int{publicEval}, evals1BigInt...)
	} else {
		fullEvals1 = append([]*big.Int{}, evals1BigInt...)
	}
	fullEvals1 = append(fullEvals1, blindingEval)

	// ---------------------------------------------------------------
	// 6. zkWHIR verify (first commitment)
	//    weightsLen: 3 (A,B,C) + optional public + 1 blinding
	//    numPolynomials: 1 (single commitment)
	// ---------------------------------------------------------------
	zkWhirParams := newZKWhirVerifyParams(1, hasPublicInputs)
	zkWhirData1, err := nativeZKWhirVerify(nimue, config, blindedCommitmentWhirConfig, blindingCommitmentWhirConfig, zkWhirParams, blindedCommitment, blindingCommitment, fullEvals1)
	if err != nil {
		return fmt.Errorf("zkWHIR verify commitment 1: %w", err)
	}

	// ---------------------------------------------------------------
	// 7. If dual mode: zkWHIR verify (second commitment)
	//    weights_2 has no public weight and no blinding weight → 3 weights
	// ---------------------------------------------------------------
	var dualData *DualCommitmentData
	if config.NumChallenges > 0 {
		// Commitment 2 has 3 base weights (A,B,C) + 1 challenge weight if challenge_eval exists.
		evals2WithChallenge := evals2BigInt
		weightsLen2 := 3
		if challengeEval != nil {
			evals2WithChallenge = append(evals2WithChallenge, challengeEval)
			weightsLen2 = 4
		}
		zkWhirParams2 := ZKWhirVerifyParams{NumPolynomials: 1, WeightsLen: weightsLen2}
		zkWhirData2, err := nativeZKWhirVerify(nimue, config, blindedCommitmentWhirConfig, blindingCommitmentWhirConfig, zkWhirParams2, blindedCommitment, blindingCommitment, evals2WithChallenge)
		if err != nil {
			return fmt.Errorf("zkWHIR verify commitment 2: %w", err)
		}
		dualData = &DualCommitmentData{
			Evals2BigInt:       evals2BigInt,
			BlindedMerkleData:  *zkWhirData2.BlindedMerkleData,
			BlindingMerkleData: *zkWhirData2.BlindingMerkleData,
		}
	}
	// ---------------------------------------------------------------
	// 8. Remaining transcript consumed. Log status.
	// ---------------------------------------------------------------
	remainingHints := nimue.hints.Len()
	remainingTranscript := len(nimue.nargString)
	fmt.Printf("Native transcript replay complete. Remaining: %d hint bytes, %d transcript bytes\n", remainingHints, remainingTranscript)

	interner, err := ParseInterner(r1cs)
	if err != nil {
		return fmt.Errorf("parse interner: %w", err)
	}

	if err := verifyCircuit(config, pk, vk, r1cs, interner, buildOps, config.PublicInputs, *zkWhirData1.BlindedMerkleData, *zkWhirData1.BlindingMerkleData, dualData); err != nil {
		return fmt.Errorf("verify circuit: %w", err)
	}

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
func nativeRunSumcheckVerifier(nimue *NativeNimue, m0 int) (*NativeSumcheckData, error) {
	// r = verifier_message_vec(m0)
	r, err := nimue.FillChallengeScalars(m0)
	if err != nil {
		return nil, fmt.Errorf("r: %w", err)
	}

	// sum_g = prover_message()
	sumGSlice, err := nimue.FillNextScalars(1)
	if err != nil {
		return nil, fmt.Errorf("sum_g: %w", err)
	}
	sumG := sumGSlice[0]

	// rho = verifier_message()
	rhoSlice, err := nimue.FillChallengeScalars(1)
	if err != nil {
		return nil, fmt.Errorf("rho: %w", err)
	}
	rho := rhoSlice[0]

	// saved_val = rho * sum_g
	savedVal := new(big.Int).Mul(rho, sumG)
	savedVal.Mod(savedVal, bn254Modulus)

	alpha := make([]*big.Int, m0)

	for i := range m0 {
		// Read 4 cubic polynomial coefficients
		coeffSlice, err := nimue.FillNextScalars(4)
		if err != nil {
			return nil, fmt.Errorf("hhat coeff round %d: %w", i, err)
		}
		var hhat [4]*big.Int
		hhat[0] = coeffSlice[0]
		hhat[1] = coeffSlice[1]
		hhat[2] = coeffSlice[2]
		hhat[3] = coeffSlice[3]

		// alpha_i = verifier_message()
		alphaSlice, err := nimue.FillChallengeScalars(1)
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

	// blinding_eval = prover_message()
	blindingSlice, err := nimue.FillNextScalars(1)
	if err != nil {
		return nil, fmt.Errorf("blinding_eval: %w", err)
	}
	blindingEval := blindingSlice[0]

	// f_at_alpha = saved_val - rho * blinding_eval
	rhoBE := new(big.Int).Mul(rho, blindingEval)
	rhoBE.Mod(rhoBE, bn254Modulus)
	fAtAlpha := new(big.Int).Sub(savedVal, rhoBE)
	fAtAlpha.Mod(fAtAlpha, bn254Modulus)
	// Ensure non-negative result (Go's Mod can return negative for negative inputs)
	if fAtAlpha.Sign() < 0 {
		fAtAlpha.Add(fAtAlpha, bn254Modulus)
	}

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
	// Merkle proof data for each WHIR verification (blinded and blinding).
	BlindedMerkleData  *whir.WhirMerkleData
	BlindingMerkleData *whir.WhirMerkleData
	// FinalClaim from the blinded WHIR verification.
	BlindedFinalClaim NativeFinalClaim
}

// nativeIRSCommitVerify replays the initial_committer.verify() transcript
// operations: squeeze in-domain challenge indices, read submatrix hint, read
// Merkle proof hints.
func nativeIRSCommitVerify(
	nimue *NativeNimue,
	numQueries int,
	domainSize int,
	foldingFactorPower int,
) ([]int, error) {
	// in_domain_challenges: squeeze challenge bytes → query indices
	indices, err := nativeGetStirChallenges(nimue, domainSize/foldingFactorPower, numQueries, false)
	if err != nil {
		return nil, fmt.Errorf("initial in-domain challenges: %w", err)
	}

	var submatrix []Fp256
	if err = nimue.ProverHintArk(&submatrix); err != nil {
		return nil, fmt.Errorf("initial submatrix: %w", err)
	}

	// matrix_commit.verify: read Merkle proof from hints
	foldedDomainSize := domainSize / foldingFactorPower
	treeHeight := bits.Len(uint(foldedDomainSize)) - 1
	dedupedIndices := make([]int, len(indices))
	copy(dedupedIndices, indices)
	sort.Ints(dedupedIndices)
	dedupedIndices = dedup(dedupedIndices)

	_, err = consumeMerkleHints(nimue, dedupedIndices, treeHeight)
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
	nimue *NativeNimue,
	config Config,
	blindedWhirParams WHIRParams,
	blindingWhirParams WHIRParams,
	params ZKWhirVerifyParams,
	blindedCommitment *NativeCommitment,
	blindingCommitment *NativeCommitment,
	evaluations []*big.Int,
) (*NativeZKWhirData, error) {
	data := &NativeZKWhirData{}

	numWitnessVariables := blindedWhirParams.MVParamsNumberOfVariables
	interleavingDepth := 1 << blindedWhirParams.FoldingFactorArray[0]

	bc, err := nimue.FillChallengeScalars(1)
	if err != nil {
		return nil, fmt.Errorf("blinding_challenge: %w", err)
	}
	data.BlindingChallenge = bc[0]

	// w_folded_blinding_evals = prover_messages_vec(num_w_folded_evals)
	// num_w_folded_evals = weights.len() * num_polynomials * (μ + 1)
	numWFoldedEvals := params.WeightsLen * params.NumPolynomials * (numWitnessVariables + 1)
	wfbe, err := nimue.FillNextScalars(numWFoldedEvals)
	if err != nil {
		return nil, fmt.Errorf("w_folded_blinding_evals: %w", err)
	}
	data.WFoldedBlindingEvals = wfbe

	mc, err := nimue.FillChallengeScalars(1)
	if err != nil {
		return nil, fmt.Errorf("masking_challenge: %w", err)
	}
	data.MaskingChallenge = mc[0]

	indices, err := nativeIRSCommitVerify(
		nimue,
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

	tau1Slice, err := nimue.FillChallengeScalars(1)
	if err != nil {
		return nil, fmt.Errorf("tau1: %w", err)
	}
	data.Tau1 = tau1Slice[0]

	tau2Slice, err := nimue.FillChallengeScalars(1)
	if err != nil {
		return nil, fmt.Errorf("tau2: %w", err)
	}
	data.Tau2 = tau2Slice[0]

	// Per-gamma evaluation loop
	// For each gamma in h_gammas:
	//   For each polynomial:
	//     m_eval      = prover_message()
	//     g_hat_evals = prover_message() × num_witness_variables
	evalsPerPoly := 1 + numWitnessVariables // m_eval + g_hat_evals
	data.PerGammaEvals = make([][][]*big.Int, hGammasCount)
	for g := range hGammasCount {
		data.PerGammaEvals[g] = make([][]*big.Int, params.NumPolynomials)
		for p := range params.NumPolynomials {
			vals, err := nimue.FillNextScalars(evalsPerPoly)
			if err != nil {
				return nil, fmt.Errorf("gamma %d poly %d evals: %w", g, p, err)
			}
			data.PerGammaEvals[g][p] = vals
		}
	}

	// combined_claims = prover_messages_vec(num_polynomials)
	// batched_h_claims = prover_messages_vec(num_polynomials)
	data.CombinedClaims, err = nimue.FillNextScalars(params.NumPolynomials)
	if err != nil {
		return nil, fmt.Errorf("combined_claims: %w", err)
	}

	data.BatchedHClaims, err = nimue.FillNextScalars(params.NumPolynomials)
	if err != nil {
		return nil, fmt.Errorf("batched_h_claims: %w", err)
	}

	// blinded_commitment.verify() — full WHIR verification
	// Verifies the witness polynomial commitment using NativeWhirVerify.
	// numLinearForms excludes the blinding weight (last in WeightsLen) because
	// the blinding evaluation is not part of the external evaluations slice.
	//
	// Build modified_evaluations = evaluations + m_evals, matching
	// Rust whir_zk/verifier.rs: modified_evaluations[i] = evaluations[i] + m_evals[i]
	// where m_evals[i] is the first element of each (μ+1)-sized block in wFoldedBlindingEvals.
	blockSize := numWitnessVariables + 1
	modifiedEvaluations := make([]*big.Int, len(evaluations))
	for i, eval := range evaluations {
		mEval := data.WFoldedBlindingEvals[i*blockSize]
		modifiedEvaluations[i] = frAdd(eval, mEval)
	}
	blindedResult, err := NativeWhirVerify(
		nimue,
		blindedWhirParams,
		config.BlindedCommitmentWhirConfig,
		[]*NativeCommitment{blindedCommitment},
		modifiedEvaluations,
	)
	if err != nil {
		return nil, fmt.Errorf("blinded_commitment verify: %w", err)
	}

	// blinding_commitment.verify() — full WHIR verification
	// Verifies the blinding polynomial commitment using NativeWhirVerify.
	// The evaluations are all_expected_blinding_claims, which is the
	// concatenation of:
	//   - expected_batched_blinding_subproof_claims: accumulated m_claims
	//     and g_hat_claims from the per-gamma evaluation loop, interleaved
	//     as [m_0, g_hat_0..., m_1, g_hat_1..., ...] (num_polynomials *
	//     (1 + num_witness_variables) elements)
	//   - w_folded_blinding_evals: parsed from transcript at step 2

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
		nimue,
		blindingWhirParams,
		config.BlindingCommitmentWhirConfig,
		[]*NativeCommitment{blindingCommitment},
		blindingEvaluations,
	)
	if err != nil {
		return nil, fmt.Errorf("blinding_commitment verify: %w", err)
	}

	data.BlindedMerkleData = blindedResult.MerkleData
	data.BlindingMerkleData = blindingResult.MerkleData
	data.BlindedFinalClaim = blindedResult.FinalClaim

	return data, nil
}

// ---------------------------------------------------------------------------
// Native protocol replay helpers
// ---------------------------------------------------------------------------
func nativeParseBatchedCommitment(nimue *NativeNimue, whirParams WHIRParams) (
	rootHash *big.Int,
	oodPoints []*big.Int,
	oodAnswers [][]*big.Int,
	err error,
) {
	roots, e := nimue.FillNextScalars(1)
	if e != nil {
		err = e
		return
	}
	rootHash = roots[0]

	oodSamples := whirParams.RoundParametersOODSamples[0]
	oodPts, e := nimue.FillChallengeScalars(oodSamples)
	if e != nil {
		err = e
		return
	}
	oodPoints = oodPts

	oodAnswers = make([][]*big.Int, whirParams.BatchSize*oodSamples)
	for i := range whirParams.BatchSize * oodSamples {
		ans, e := nimue.FillNextScalars(1)
		if e != nil {
			err = e
			return
		}
		oodAnswers[i] = ans
	}

	return
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
