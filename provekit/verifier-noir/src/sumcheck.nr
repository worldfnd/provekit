//! Spartan sumcheck verifier.
//!
//! Mirrors `provekit/verifier/src/whir_r1cs.rs::run_sumcheck_verifier`:
//!
//!   1. Squeeze `M0` initial challenges `r`.
//!   2. Absorb the prover's claimed sum `sum_g`.
//!   3. Squeeze the batching challenge `rho`; set `saved = rho * sum_g`.
//!   4. For each of `M0` rounds:
//!        a. Absorb the cubic polynomial `h_i` (4 coefficients).
//!        b. Squeeze the round challenge `alpha_i`.
//!        c. Assert `h_i(0) + h_i(1) == saved`.
//!        d. Update `saved = h_i(alpha_i)`.
//!   5. Absorb `blinding_eval`.
//!   6. Return `(r, alpha, blinding_eval, f_at_alpha)` where
//!      `f_at_alpha = saved - rho * blinding_eval`.
//!
//! Cross-implementation KAT lives in
//! `provekit/verifier-noir-test/tests/sumcheck_kat.rs`.

use crate::transcript::Transcript;

/// Evaluate a cubic polynomial via Horner's method.
/// `poly = [c0, c1, c2, c3]` represents `c0 + c1*x + c2*x^2 + c3*x^3`.
pub fn eval_cubic_poly(poly: [Field; 4], point: Field) -> Field {
    poly[0] + point * (poly[1] + point * (poly[2] + point * poly[3]))
}

/// Multilinear extension of the equality polynomial:
/// `eq(r, alpha) = product over i of (r[i]*alpha[i] + (1 - r[i])*(1 - alpha[i]))`.
pub fn calculate_eq<let N: u32>(r: [Field; N], alpha: [Field; N]) -> Field {
    let mut acc: Field = 1;
    for i in 0..N {
        acc *= r[i] * alpha[i] + (1 - r[i]) * (1 - alpha[i]);
    }
    acc
}

/// Result of a successful sumcheck verification.
pub struct SumcheckResult<let M0: u32> {
    pub r: [Field; M0],
    pub alpha: [Field; M0],
    pub blinding_eval: Field,
    pub f_at_alpha: Field,
}

/// Verify a Spartan sumcheck against a Fiat-Shamir transcript.
///
/// `h_polys[i]` is the cubic polynomial sent by the prover in round i;
/// `sum_g` is the claimed initial sum; `blinding_eval` is the final
/// blinding evaluation hint. All come from the proof bytes parsed by the
/// codegen tool.
pub fn run_sumcheck_verifier<let M0: u32>(
    transcript: &mut Transcript,
    sum_g: Field,
    h_polys: [[Field; 4]; M0],
    blinding_eval: Field,
) -> SumcheckResult<M0> {
    // Phase 1: squeeze initial challenges r.
    let mut r: [Field; M0] = [0; M0];
    for i in 0..M0 {
        r[i] = transcript.squeeze_field();
    }

    // Phase 2: absorb sum, squeeze rho, initialize saved.
    transcript.absorb_field(sum_g);
    let rho = transcript.squeeze_field();
    let mut saved = rho * sum_g;

    // Phase 3: per-round challenge derivation + soundness checks.
    let mut alpha: [Field; M0] = [0; M0];
    for i in 0..M0 {
        let h_i = h_polys[i];
        for j in 0..4 {
            transcript.absorb_field(h_i[j]);
        }
        let alpha_i = transcript.squeeze_field();
        alpha[i] = alpha_i;

        let h_at_zero = eval_cubic_poly(h_i, 0);
        let h_at_one = eval_cubic_poly(h_i, 1);
        assert(saved == h_at_zero + h_at_one);

        saved = eval_cubic_poly(h_i, alpha_i);
    }

    // Phase 4: absorb blinding hint, derive f_at_alpha.
    transcript.absorb_field(blinding_eval);
    let f_at_alpha = saved - rho * blinding_eval;

    SumcheckResult { r, alpha, blinding_eval, f_at_alpha }
}

// --- in-circuit unit tests for pure functions ---

#[test]
fn eval_cubic_poly_horner() {
    // p(x) = 1 + 2x + 3x^2 + 4x^3; p(2) = 1 + 4 + 12 + 32 = 49.
    let out = eval_cubic_poly([1, 2, 3, 4], 2);
    assert(out == 49);
}

#[test]
fn calculate_eq_boolean_identity() {
    // eq(r, r) where r is boolean = 1.
    let r: [Field; 3] = [0, 1, 0];
    let alpha: [Field; 3] = [0, 1, 0];
    assert(calculate_eq(r, alpha) == 1);
}

#[test]
fn calculate_eq_boolean_orthogonal() {
    // eq(r, flipped) where flipped flips every bit = 0.
    let r: [Field; 3] = [0, 1, 0];
    let alpha: [Field; 3] = [1, 0, 1];
    assert(calculate_eq(r, alpha) == 0);
}

#[test]
fn calculate_eq_non_boolean() {
    // r = [2, 3], alpha = [4, 5]
    // term0 = 2*4 + (-1)*(-3) = 8 + 3 = 11
    // term1 = 3*5 + (-2)*(-4) = 15 + 8 = 23
    // product = 253
    let r: [Field; 2] = [2, 3];
    let alpha: [Field; 2] = [4, 5];
    assert(calculate_eq(r, alpha) == 253);
}

// --- in-circuit sumcheck KAT (self-consistent under new 2-lane semantics) ---
//
// The previous frozen KAT pinned the OLD lane-only `squeeze_field` semantics.
// After the desync fix `squeeze_field` now squeezes 2 lanes (64 bytes) to
// match spongefish's Fr challenge. The frozen constants are stale; we
// regenerate cross-impl values in `provekit/verifier-noir-test/tests/
// sumcheck_kat.rs`.
//
// In-circuit we keep a runtime self-consistency check: round 0's polynomial
// is set so `h_0(0) + h_0(1) == rho * sum_g`, and round 1's polynomial is set
// so `h_1(0) + h_1(1) == h_0(alpha_0)`. This requires squeezing rho and
// alpha_0 from a fresh transcript inside the test (matching exactly what the
// verifier will see) and computing h_polys on the fly.
//
// TODO(verifier-noir-test): refresh sumcheck_kat.rs to use the new 2-lane
// `squeeze_field` semantics so we get a frozen-value cross-impl check too.

#[test]
fn sumcheck_verifier_runtime_consistent() {
    // Predict rho and alpha_0 by running a parallel sponge.
    let mut probe = Transcript::new();
    // run_sumcheck_verifier squeezes M0 challenges r, then absorbs sum_g,
    // then squeezes rho. For M0 = 2 we squeeze twice then absorb then squeeze.
    let _r0 = probe.squeeze_field();
    let _r1 = probe.squeeze_field();
    probe.absorb_field(12);
    let rho = probe.squeeze_field();

    // Construct round 0: h_0 = [saved/2, 0, 0, 0] so h_0(0) + h_0(1) = saved.
    let saved0 = rho * 12;
    let two_inv: Field = 1 / 2;
    let h0_c0 = saved0 * two_inv;
    let h0: [Field; 4] = [h0_c0, 0, 0, 0];

    // After absorbing h_0 we squeeze alpha_0.
    for j in 0..4 {
        probe.absorb_field(h0[j]);
    }
    let alpha0 = probe.squeeze_field();
    // saved1 = h_0(alpha_0) = h0_c0 (constant poly).
    let saved1 = h0_c0;
    let h1_c0 = saved1 * two_inv;
    let h1: [Field; 4] = [h1_c0, 0, 0, 0];
    let _ = alpha0; // tracked by transcript only

    let h_polys: [[Field; 4]; 2] = [h0, h1];

    // Now run the real verifier on a fresh transcript with the same sum_g
    // and constructed h_polys; it must succeed.
    let mut t = Transcript::new();
    let _result = run_sumcheck_verifier::<2>(&mut t, 12, h_polys, 7);
}
