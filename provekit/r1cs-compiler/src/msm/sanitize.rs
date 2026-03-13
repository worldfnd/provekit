//! Degenerate-case detection and sanitization helpers for MSM point-scalar
//! pairs.

use {
    super::{curve::CurveParams, Limbs},
    crate::{
        constraint_helpers::{compute_boolean_or, constrain_boolean, select_witness},
        msm::multi_limb_arith::compute_is_zero,
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::Field,
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
/// Used by the native path where coordinates fit in a single field element.
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
        px_limbs:        vec![san.px],
        py_limbs:        vec![san.py],
        s_lo:            san.s_lo,
        s_hi:            san.s_hi,
        curve_a:         curve.curve_a,
        field_modulus_p: curve.field_modulus_p,
        num_limbs:       1,
        limb_bits:       0,
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

/// Multi-limb sanitized inputs for non-native MSM.
pub(super) struct SanitizedInputsMultiLimb {
    pub px_limbs: Limbs,
    pub py_limbs: Limbs,
    pub s_lo:     usize,
    pub s_hi:     usize,
    pub is_skip:  usize,
}

/// Sanitize a non-native point-scalar pair at the limb level.
///
/// Detects degenerate cases and replaces the point with the generator
/// (as limbs) and scalar with 1 when degenerate. This avoids truncating
/// generator coordinates that exceed BN254_Fr.
pub(super) fn sanitize_point_scalar_multi_limb(
    compiler: &mut NoirToR1CSCompiler,
    px_limbs: Limbs,
    py_limbs: Limbs,
    s_lo: usize,
    s_hi: usize,
    inf_flag: usize,
    gen_x_limb_wits: &[usize],
    gen_y_limb_wits: &[usize],
    zero: usize,
    one: usize,
) -> SanitizedInputsMultiLimb {
    let n = px_limbs.len();
    let is_skip = detect_skip(compiler, s_lo, s_hi, inf_flag);

    let mut san_px = Limbs::new(n);
    let mut san_py = Limbs::new(n);
    for i in 0..n {
        san_px[i] = select_witness(compiler, is_skip, px_limbs[i], gen_x_limb_wits[i]);
        san_py[i] = select_witness(compiler, is_skip, py_limbs[i], gen_y_limb_wits[i]);
    }

    SanitizedInputsMultiLimb {
        px_limbs: san_px,
        py_limbs: san_py,
        s_lo: select_witness(compiler, is_skip, s_lo, one),
        s_hi: select_witness(compiler, is_skip, s_hi, zero),
        is_skip,
    }
}

/// Emit an `EcScalarMulHint` with multi-limb inputs/outputs and sanitize.
///
/// When `is_skip=1`, each output limb is replaced with the corresponding
/// generator limb. Returns `(rx_limbs, ry_limbs)` as `Limbs`.
pub(super) fn emit_ec_scalar_mul_hint_and_sanitize_multi_limb(
    compiler: &mut NoirToR1CSCompiler,
    san: &SanitizedInputsMultiLimb,
    gen_x_limb_wits: &[usize],
    gen_y_limb_wits: &[usize],
    num_limbs: usize,
    limb_bits: u32,
    range_checks: &mut std::collections::BTreeMap<u32, Vec<usize>>,
    curve: &CurveParams,
) -> (Limbs, Limbs) {
    let hint_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::EcScalarMulHint {
        output_start: hint_start,
        px_limbs: san.px_limbs.as_slice().to_vec(),
        py_limbs: san.py_limbs.as_slice().to_vec(),
        s_lo: san.s_lo,
        s_hi: san.s_hi,
        curve_a: curve.curve_a,
        field_modulus_p: curve.field_modulus_p,
        num_limbs: num_limbs as u32,
        limb_bits,
    });

    let mut rx = Limbs::new(num_limbs);
    let mut ry = Limbs::new(num_limbs);
    for i in 0..num_limbs {
        let rx_hint = hint_start + i;
        let ry_hint = hint_start + num_limbs + i;
        // Range-check hint output limbs
        range_checks.entry(limb_bits).or_default().push(rx_hint);
        range_checks.entry(limb_bits).or_default().push(ry_hint);
        // Sanitize: select between hint output and generator
        rx[i] = select_witness(compiler, san.is_skip, rx_hint, gen_x_limb_wits[i]);
        ry[i] = select_witness(compiler, san.is_skip, ry_hint, gen_y_limb_wits[i]);
    }

    (rx, ry)
}
