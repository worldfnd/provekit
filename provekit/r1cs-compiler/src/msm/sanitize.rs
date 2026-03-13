//! Degenerate-case detection, sanitization, and bit decomposition helpers
//! for MSM point-scalar pairs.

use {
    super::curve::CurveParams,
    crate::{
        constraint_helpers::{compute_boolean_or, constrain_boolean, select_witness},
        msm::multi_limb_arith::compute_is_zero,
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::{AdditiveGroup, Field},
    provekit_common::{
        witness::{SumTerm, WitnessBuilder},
        FieldElement,
    },
};

/// Detects whether a point-scalar pair is degenerate (scalar=0 or point at
/// infinity). Constrains `inf_flag` to boolean. Returns `is_skip` (1 if
/// degenerate).
fn detect_skip(
    compiler: &mut NoirToR1CSCompiler,
    s_lo: usize,
    s_hi: usize,
    inf_flag: usize,
) -> usize {
    constrain_boolean(compiler, inf_flag);
    let is_zero_s_lo = compute_is_zero(compiler, s_lo);
    let is_zero_s_hi = compute_is_zero(compiler, s_hi);
    let s_is_zero = compiler.add_product(is_zero_s_lo, is_zero_s_hi);
    compute_boolean_or(compiler, s_is_zero, inf_flag)
}

/// Sanitized point-scalar inputs after degenerate-case detection.
pub(super) struct SanitizedInputs {
    pub px:      usize,
    pub py:      usize,
    pub s_lo:    usize,
    pub s_hi:    usize,
    pub is_skip: usize,
}

/// Detects degenerate cases (scalar=0 or point at infinity) and replaces
/// the point with the generator G and scalar with 1 when degenerate.
pub(super) fn sanitize_point_scalar(
    compiler: &mut NoirToR1CSCompiler,
    px: usize,
    py: usize,
    s_lo: usize,
    s_hi: usize,
    inf_flag: usize,
    gen_x: usize,
    gen_y: usize,
    zero: usize,
    one: usize,
) -> SanitizedInputs {
    let is_skip = detect_skip(compiler, s_lo, s_hi, inf_flag);
    SanitizedInputs {
        px: select_witness(compiler, is_skip, px, gen_x),
        py: select_witness(compiler, is_skip, py, gen_y),
        s_lo: select_witness(compiler, is_skip, s_lo, one),
        s_hi: select_witness(compiler, is_skip, s_hi, zero),
        is_skip,
    }
}

/// Negate a y-coordinate and conditionally select based on a sign flag.
/// Returns `(y_eff, neg_y_eff)` where:
///   - if `neg_flag=0`: `y_eff = y`,     `neg_y_eff = -y`
///   - if `neg_flag=1`: `y_eff = -y`,    `neg_y_eff = y`
pub(super) fn negate_y_signed_native(
    compiler: &mut NoirToR1CSCompiler,
    neg_flag: usize,
    y: usize,
) -> (usize, usize) {
    constrain_boolean(compiler, neg_flag);
    let neg_y = compiler.add_sum(vec![SumTerm(Some(-FieldElement::ONE), y)]);
    let y_eff = select_witness(compiler, neg_flag, y, neg_y);
    let neg_y_eff = select_witness(compiler, neg_flag, neg_y, y);
    (y_eff, neg_y_eff)
}

/// Emit an `EcScalarMulHint` and sanitize the result point.
/// When `is_skip=1`, the result is swapped to the generator point.
pub(super) fn emit_ec_scalar_mul_hint_and_sanitize(
    compiler: &mut NoirToR1CSCompiler,
    san: &SanitizedInputs,
    gen_x_witness: usize,
    gen_y_witness: usize,
    curve: &CurveParams,
) -> (usize, usize) {
    let hint_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::EcScalarMulHint {
        output_start:    hint_start,
        px:              san.px,
        py:              san.py,
        s_lo:            san.s_lo,
        s_hi:            san.s_hi,
        curve_a:         curve.curve_a,
        field_modulus_p: curve.field_modulus_p,
    });
    let rx = select_witness(compiler, san.is_skip, hint_start, gen_x_witness);
    let ry = select_witness(compiler, san.is_skip, hint_start + 1, gen_y_witness);
    (rx, ry)
}

/// Allocates a FakeGLV hint and returns `(s1, s2, neg1, neg2)` witness indices.
pub(super) fn emit_fakeglv_hint(
    compiler: &mut NoirToR1CSCompiler,
    s_lo: usize,
    s_hi: usize,
    curve: &CurveParams,
) -> (usize, usize, usize, usize) {
    let glv_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::FakeGLVHint {
        output_start: glv_start,
        s_lo,
        s_hi,
        curve_order: curve.curve_order_n,
    });
    (glv_start, glv_start + 1, glv_start + 2, glv_start + 3)
}

/// Signed-bit decomposition for wNAF scalar multiplication.
///
/// Decomposes `scalar` into `num_bits` sign-bits b_i ∈ {0,1} and a skew ∈ {0,1}
/// such that the signed digits d_i = 2*b_i - 1 ∈ {-1, +1} satisfy:
///   scalar = Σ d_i * 2^i - skew
///
/// Reconstruction constraint (1 linear R1CS):
///   scalar + skew + (2^n - 1) = Σ b_i * 2^{i+1}
///
/// All bits and skew are boolean-constrained.
///
/// # Limitation
/// The prover's `SignedBitHint` solver reads the scalar as a `u128` (lower
/// 128 bits of the field element). This is correct for FakeGLV half-scalars
/// (≤128 bits for 256-bit curves) but would silently truncate if `num_bits`
/// exceeds 128. The R1CS reconstruction constraint would then fail.
pub(super) fn decompose_signed_bits(
    compiler: &mut NoirToR1CSCompiler,
    scalar: usize,
    num_bits: usize,
) -> (Vec<usize>, usize) {
    let start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::SignedBitHint {
        output_start: start,
        scalar,
        num_bits,
    });
    let bits: Vec<usize> = (start..start + num_bits).collect();
    let skew = start + num_bits;

    // Boolean-constrain each bit and skew
    for &b in &bits {
        constrain_boolean(compiler, b);
    }
    constrain_boolean(compiler, skew);

    // Reconstruction: scalar + skew + (2^n - 1) = Σ b_i * 2^{i+1}
    // Rearranged as: scalar + skew + (2^n - 1) - Σ b_i * 2^{i+1} = 0
    let one = compiler.witness_one();
    let two = FieldElement::from(2u64);
    let constant = two.pow([num_bits as u64]) - FieldElement::ONE;
    let mut b_terms: Vec<(FieldElement, usize)> = bits
        .iter()
        .enumerate()
        .map(|(i, &b)| (-two.pow([(i + 1) as u64]), b))
        .collect();
    b_terms.push((FieldElement::ONE, scalar));
    b_terms.push((FieldElement::ONE, skew));
    b_terms.push((constant, one));
    compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, one)], &b_terms, &[(
            FieldElement::ZERO,
            one,
        )]);

    (bits, skew)
}
