//! Native-field MSM path: hint-verified EC ops with signed-bit wNAF.
//!
//! Used when `curve.is_native_field()` — the curve's base field matches the
//! R1CS native field (e.g. Grumpkin over BN254). Field operations are free
//! (single native witness each), so EC operations use prover hints verified
//! via raw R1CS constraints instead of expensive field inversions.
//!
//! ## Key techniques
//!
//! - **Hint-verified EC ops**: point_double (4W+4C), point_add (3W+3C), and
//!   on-curve checks (2W+3C) use prover-supplied (lambda, x3, y3) hints
//!   verified by the EC equations directly as R1CS constraints.
//! - **FakeGLV**: each 256-bit scalar is decomposed into two ~128-bit
//!   half-scalars (s1, s2) via half-GCD, verified by a scalar relation mod the
//!   curve order.
//! - **Signed-bit wNAF (w=1)**: each half-scalar is decomposed into signed bits
//!   d_i ∈ {-1, +1}, eliminating zero-digit handling. A skew bit corrects the
//!   bias post-loop.
//! - **Merged doubling**: all points share a single doubling per bit, saving 4W
//!   per extra point per bit.
//!
//! ## Phases
//!
//! 1. **Preprocessing**: per-point sanitization (degenerate-case replacement),
//!    on-curve checks, FakeGLV decomposition, signed-bit decomposition,
//!    y-negation based on sign flags.
//! 2. **Merged scalar mul**: single loop from MSB to LSB with one shared
//!    doubling + per-point P/R branch adds. Skew corrections after loop.
//!    Identity check: final accumulator must equal the known offset.
//! 3. **Scalar relations**: per-point verification that (-1)^neg1·|s1| +
//!    (-1)^neg2·|s2|·s ≡ 0 (mod curve_order).
//! 4. **Accumulation**: adds each point's scalar-mul result to an accumulator
//!    (skipping degenerate points), subtracts the offset, constrains outputs.

use {
    super::{
        curve, ec_points,
        sanitize::{
            emit_ec_scalar_mul_hint_and_sanitize, emit_fakeglv_hint, negate_y_signed_native,
            sanitize_point_scalar,
        },
        scalar_relation,
    },
    crate::{
        constraint_helpers::{
            add_constant_witness, constrain_equal, constrain_to_constant, select_witness,
        },
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::AdditiveGroup,
    curve::CurveParams,
    provekit_common::FieldElement,
    std::collections::BTreeMap,
};

/// Per-point preprocessed data for the merged native scalar mul loop.
///
/// Holds the inputs needed by `scalar_mul_merged_native_wnaf` to process
/// one point's P and R branches inside the shared-doubling loop.
struct NativePointData {
    px:         usize,
    py_eff:     usize,
    neg_py_eff: usize,
    s1_bits:    Vec<usize>,
    s1_skew:    usize,
    rx:         usize,
    ry_eff:     usize,
    neg_ry_eff: usize,
    s2_bits:    Vec<usize>,
    s2_skew:    usize,
}

/// Native-field MSM with merged-loop optimization.
///
/// All points share a single doubling per bit, saving 4*(n-1) constraints
/// per bit of the half-scalar.
pub(super) fn process_multi_point_native(
    compiler: &mut NoirToR1CSCompiler,
    point_wits: &[usize],
    scalar_wits: &[usize],
    outputs: (usize, usize, usize),
    n_points: usize,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    curve: &CurveParams,
) {
    let (out_x, out_y, out_inf) = outputs;
    let one = compiler.witness_one();

    // Generator constants for sanitization
    let gen_x_fe = curve::curve_native_point_fe(&curve.generator.0);
    let gen_y_fe = curve::curve_native_point_fe(&curve.generator.1);
    let gen_x_witness = add_constant_witness(compiler, gen_x_fe);
    let gen_y_witness = add_constant_witness(compiler, gen_y_fe);
    let zero_witness = add_constant_witness(compiler, FieldElement::ZERO);

    let mut all_skipped: Option<usize> = None;
    let mut native_points: Vec<NativePointData> = Vec::new();
    let mut scalar_rel_inputs: Vec<(usize, usize, usize, usize, usize, usize)> = Vec::new();
    let mut accum_inputs: Vec<(usize, usize, usize)> = Vec::new();

    // Phase 1: Per-point preprocessing
    for i in 0..n_points {
        let san = sanitize_point_scalar(
            compiler,
            point_wits[3 * i],
            point_wits[3 * i + 1],
            scalar_wits[2 * i],
            scalar_wits[2 * i + 1],
            point_wits[3 * i + 2],
            gen_x_witness,
            gen_y_witness,
            zero_witness,
            one,
        );

        all_skipped = Some(match all_skipped {
            None => san.is_skip,
            Some(prev) => compiler.add_product(prev, san.is_skip),
        });

        let (sanitized_rx, sanitized_ry) = emit_ec_scalar_mul_hint_and_sanitize(
            compiler,
            &san,
            gen_x_witness,
            gen_y_witness,
            curve,
        );

        // On-curve checks
        ec_points::verify_on_curve_native(compiler, san.px, san.py, curve);
        ec_points::verify_on_curve_native(compiler, sanitized_rx, sanitized_ry, curve);

        // FakeGLV decomposition + signed-bit decomposition
        let (s1, s2, neg1, neg2) = emit_fakeglv_hint(compiler, san.s_lo, san.s_hi, curve);
        let half_bits = curve.glv_half_bits() as usize;
        let (s1_bits, s1_skew) = super::decompose_signed_bits(compiler, s1, half_bits);
        let (s2_bits, s2_skew) = super::decompose_signed_bits(compiler, s2, half_bits);

        // Y-negation
        let (py_eff, neg_py_eff) = negate_y_signed_native(compiler, neg1, san.py);
        let (ry_eff, neg_ry_eff) = negate_y_signed_native(compiler, neg2, sanitized_ry);

        native_points.push(NativePointData {
            px: san.px,
            py_eff,
            neg_py_eff,
            s1_bits,
            s1_skew,
            rx: sanitized_rx,
            ry_eff,
            neg_ry_eff,
            s2_bits,
            s2_skew,
        });

        scalar_rel_inputs.push((san.s_lo, san.s_hi, s1, s2, neg1, neg2));
        accum_inputs.push((sanitized_rx, sanitized_ry, san.is_skip));
    }

    // Phase 2: Per-point scalar mul verification
    //
    // Each point gets its own accumulator and identity check. This ensures
    // per-point soundness: b_i * (R_i - scalar_i * P_i) = O with b_i ≠ 0
    // implies R_i = scalar_i * P_i for each point independently.
    let half_bits = curve.glv_half_bits() as usize;
    let offset_x_fe = curve::curve_native_point_fe(&curve.offset_point.0);
    let offset_y_fe = curve::curve_native_point_fe(&curve.offset_point.1);
    let (acc_off_x_raw, acc_off_y_raw) = curve.accumulated_offset(half_bits);
    let acc_off_x_fe = curve::curve_native_point_fe(&acc_off_x_raw);
    let acc_off_y_fe = curve::curve_native_point_fe(&acc_off_y_raw);

    for pt in &native_points {
        let offset_x = add_constant_witness(compiler, offset_x_fe);
        let offset_y = add_constant_witness(compiler, offset_y_fe);

        let (ver_acc_x, ver_acc_y) = scalar_mul_merged_native_wnaf(
            compiler,
            std::slice::from_ref(pt),
            offset_x,
            offset_y,
            curve,
        );

        constrain_to_constant(compiler, ver_acc_x, acc_off_x_fe);
        constrain_to_constant(compiler, ver_acc_y, acc_off_y_fe);
    }

    // Phase 3: Per-point scalar relations
    for &(s_lo, s_hi, s1, s2, neg1, neg2) in &scalar_rel_inputs {
        scalar_relation::verify_scalar_relation(
            compiler,
            range_checks,
            s_lo,
            s_hi,
            s1,
            s2,
            neg1,
            neg2,
            curve,
        );
    }

    // Phase 4: Accumulation (same offset-based logic)
    let all_skipped = all_skipped.expect("MSM must have at least one point");

    let mut acc_x = add_constant_witness(compiler, offset_x_fe);
    let mut acc_y = add_constant_witness(compiler, offset_y_fe);

    for &(sanitized_rx, sanitized_ry, is_skip) in &accum_inputs {
        let (cand_x, cand_y) = ec_points::point_add_verified_native(
            compiler,
            acc_x,
            acc_y,
            sanitized_rx,
            sanitized_ry,
            curve,
        );
        acc_x = select_witness(compiler, is_skip, cand_x, acc_x);
        acc_y = select_witness(compiler, is_skip, cand_y, acc_y);
    }

    // Offset subtraction and output constraining
    let neg_offset_y_raw =
        curve::negate_field_element(&curve.offset_point.1, &curve.field_modulus_p);
    let neg_offset_y_fe = curve::curve_native_point_fe(&neg_offset_y_raw);
    let neg_gen_y_raw = curve::negate_field_element(&curve.generator.1, &curve.field_modulus_p);
    let neg_gen_y_fe = curve::curve_native_point_fe(&neg_gen_y_raw);

    let sub_x_off = add_constant_witness(compiler, offset_x_fe);
    let sub_x = select_witness(compiler, all_skipped, sub_x_off, gen_x_witness);

    let neg_off_y_w = add_constant_witness(compiler, neg_offset_y_fe);
    let neg_g_y_w = add_constant_witness(compiler, neg_gen_y_fe);
    let sub_y = select_witness(compiler, all_skipped, neg_off_y_w, neg_g_y_w);

    let (result_x, result_y) =
        ec_points::point_add_verified_native(compiler, acc_x, acc_y, sub_x, sub_y, curve);

    let masked_result_x = select_witness(compiler, all_skipped, result_x, zero_witness);
    let masked_result_y = select_witness(compiler, all_skipped, result_y, zero_witness);
    constrain_equal(compiler, out_x, masked_result_x);
    constrain_equal(compiler, out_y, masked_result_y);
    constrain_equal(compiler, out_inf, all_skipped);
}

/// Multi-point scalar multiplication for native field using signed-bit wNAF
/// (w=1).
///
/// Called once per point with a single-element slice for per-point
/// soundness (each point gets its own accumulator and identity check).
/// Each bit costs: 4C (double) + 2 × (1C select + 3C add) = 12C per point.
fn scalar_mul_merged_native_wnaf(
    compiler: &mut NoirToR1CSCompiler,
    points: &[NativePointData],
    offset_x: usize,
    offset_y: usize,
    curve: &CurveParams,
) -> (usize, usize) {
    let n = points[0].s1_bits.len();
    let mut acc_x = offset_x;
    let mut acc_y = offset_y;

    // wNAF loop: MSB to LSB, shared doubling
    for i in (0..n).rev() {
        // Single shared double
        let (dx, dy) = ec_points::point_double_verified_native(compiler, acc_x, acc_y, curve);
        let mut cur_x = dx;
        let mut cur_y = dy;

        // For each point: P branch + R branch
        for pt in points {
            let sel_py = select_witness(compiler, pt.s1_bits[i], pt.neg_py_eff, pt.py_eff);
            let (ax, ay) =
                ec_points::point_add_verified_native(compiler, cur_x, cur_y, pt.px, sel_py, curve);

            let sel_ry = select_witness(compiler, pt.s2_bits[i], pt.neg_ry_eff, pt.ry_eff);
            (cur_x, cur_y) =
                ec_points::point_add_verified_native(compiler, ax, ay, pt.rx, sel_ry, curve);
        }

        acc_x = cur_x;
        acc_y = cur_y;
    }

    // Skew corrections for all points
    for pt in points {
        let (sub_px, sub_py) = ec_points::point_add_verified_native(
            compiler,
            acc_x,
            acc_y,
            pt.px,
            pt.neg_py_eff,
            curve,
        );
        acc_x = select_witness(compiler, pt.s1_skew, acc_x, sub_px);
        acc_y = select_witness(compiler, pt.s1_skew, acc_y, sub_py);

        let (sub_rx, sub_ry) = ec_points::point_add_verified_native(
            compiler,
            acc_x,
            acc_y,
            pt.rx,
            pt.neg_ry_eff,
            curve,
        );
        acc_x = select_witness(compiler, pt.s2_skew, acc_x, sub_rx);
        acc_y = select_witness(compiler, pt.s2_skew, acc_y, sub_ry);
    }

    (acc_x, acc_y)
}
