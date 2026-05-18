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

// --- in-circuit sumcheck KAT ---
//
// Canonical Phase 2A sumcheck KAT:
//   transcript = fresh
//   sum_g = 12; M0 = 2
//   h_polys = constructed by the Rust replay so each round's soundness
//             assertion (h_i(0) + h_i(1) == saved) passes.
//   blinding_eval = 7
// Values constructed by the Rust sumcheck replay (h_i = [saved/2, 0, 0, 0]
// each round) so each round's soundness check holds. See
// provekit/verifier-noir-test/tests/sumcheck_kat.rs for the cross-impl guarantee.
global EXPECTED_SUMCHECK_F_AT_ALPHA: Field = 489513540466994505614179577330661230587008242067805016378633528214894665614;
global SUMCHECK_KAT_SUM_G: Field = 12;
global SUMCHECK_KAT_BLINDING_EVAL: Field = 7;
global SUMCHECK_KAT_H_POLYS: [[Field; 4]; 2] = [
    [21153972561138783463825136379261283242667852037314326819130253894253466497196, 0, 0, 0],
    [10576986280569391731912568189630641621333926018657163409565126947126733248598, 0, 0, 0],
];

#[test]
fn sumcheck_verifier_matches_frozen_kat() {
    let mut t = Transcript::new();
    let result = run_sumcheck_verifier::<2>(
        &mut t,
        SUMCHECK_KAT_SUM_G,
        SUMCHECK_KAT_H_POLYS,
        SUMCHECK_KAT_BLINDING_EVAL,
    );
    assert(result.f_at_alpha == EXPECTED_SUMCHECK_F_AT_ALPHA);
}
