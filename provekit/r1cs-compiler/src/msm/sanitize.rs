//! Degenerate-case detection and sanitization helpers for MSM point-scalar
//! pairs.

use {
    super::{curve::Curve, Limbs},
    crate::{
        constraint_helpers::{compute_boolean_or, constrain_boolean, select_witness},
        msm::multi_limb_arith::compute_is_zero,
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    provekit_common::witness::WitnessBuilder,
};

/// Detects whether a point-scalar pair is degenerate (scalar=0 or point at
/// infinity).
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

/// Allocates a FakeGLV hint and returns `(s1, s2, neg1, neg2)` witness indices.
pub(super) fn emit_fakeglv_hint<C: Curve>(
    compiler: &mut NoirToR1CSCompiler,
    s_lo: usize,
    s_hi: usize,
    curve: &C,
) -> (usize, usize, usize, usize) {
    let glv_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::FakeGLVHint {
        output_start: glv_start,
        s_lo,
        s_hi,
        curve_order: curve.curve_order_n(),
    });
    (glv_start, glv_start + 1, glv_start + 2, glv_start + 3)
}

/// Sanitized point-scalar inputs (limbed representation).
pub(super) struct SanitizedInputsMultiLimb {
    pub px_limbs: Limbs,
    pub py_limbs: Limbs,
    pub s_lo:     usize,
    pub s_hi:     usize,
    pub is_skip:  usize,
}

/// Sanitize a point-scalar pair, replacing degenerate cases with the
/// generator.
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

    let mut san_px = Limbs::new();
    let mut san_py = Limbs::new();
    for i in 0..n {
        san_px.push(select_witness(
            compiler,
            is_skip,
            px_limbs[i],
            gen_x_limb_wits[i],
        ));
        san_py.push(select_witness(
            compiler,
            is_skip,
            py_limbs[i],
            gen_y_limb_wits[i],
        ));
    }

    SanitizedInputsMultiLimb {
        px_limbs: san_px,
        py_limbs: san_py,
        s_lo: select_witness(compiler, is_skip, s_lo, one),
        s_hi: select_witness(compiler, is_skip, s_hi, zero),
        is_skip,
    }
}

/// Emit an `EcScalarMulHint` and sanitize the output limbs.
pub(super) fn emit_ec_scalar_mul_hint_and_sanitize_multi_limb<C: Curve>(
    compiler: &mut NoirToR1CSCompiler,
    san: &SanitizedInputsMultiLimb,
    gen_x_limb_wits: &[usize],
    gen_y_limb_wits: &[usize],
    num_limbs: usize,
    limb_bits: u32,
    range_checks: &mut std::collections::BTreeMap<u32, Vec<usize>>,
    curve: &C,
) -> (Limbs, Limbs) {
    let hint_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::EcScalarMulHint {
        output_start: hint_start,
        px_limbs: san.px_limbs.as_slice().to_vec(),
        py_limbs: san.py_limbs.as_slice().to_vec(),
        s_lo: san.s_lo,
        s_hi: san.s_hi,
        curve_a: curve.curve_a(),
        field_modulus_p: curve.field_modulus_p(),
        num_limbs: num_limbs as u32,
        limb_bits,
    });

    let mut rx = Limbs::new();
    let mut ry = Limbs::new();
    for i in 0..num_limbs {
        let rx_hint = hint_start + i;
        let ry_hint = hint_start + num_limbs + i;
        // Range-check hint output limbs (native field elements don't need it)
        if num_limbs > 1 {
            range_checks.entry(limb_bits).or_default().push(rx_hint);
            range_checks.entry(limb_bits).or_default().push(ry_hint);
        }
        // Sanitize: select between hint output and generator
        rx.push(select_witness(
            compiler,
            san.is_skip,
            rx_hint,
            gen_x_limb_wits[i],
        ));
        ry.push(select_witness(
            compiler,
            san.is_skip,
            ry_hint,
            gen_y_limb_wits[i],
        ));
    }

    (rx, ry)
}
