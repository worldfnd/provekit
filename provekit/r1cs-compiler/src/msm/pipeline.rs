//! Unified MSM pipeline for all curves (native and non-native).
//!
//! Orchestrates the 4-phase MSM process, generic over `E: EcOps`:
//!
//! 1. **Preprocessing**: per-point sanitization, on-curve checks, FakeGLV
//!    decomposition, signed-bit decomposition, y-negation.
//! 2. **Scalar mul verification**: per-point `scalar_mul_merged_glv` with
//!    identity check against the known accumulated offset.
//! 3. **Scalar relations**: per-point verification that (-1)^neg1·|s1| +
//!    (-1)^neg2·|s2|·s ≡ 0 (mod curve_order).
//! 4. **Accumulation**: adds each point's scalar-mul result, subtracts offset,
//!    constrains outputs.

use {
    super::{
        curve::{self, Curve},
        ec_points::{self, EcOps},
        multi_limb_ops::{MultiLimbOps, MultiLimbParams},
        sanitize::{
            emit_ec_scalar_mul_hint_and_sanitize_multi_limb, emit_fakeglv_hint,
            sanitize_point_scalar_multi_limb,
        },
        scalar_relation, Limbs, MsmLimbedOutputs,
    },
    crate::{
        constraint_helpers::{
            add_constant_witness, constrain_equal, constrain_to_constant, select_witness,
        },
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::AdditiveGroup,
    curve::decompose_to_limbs as decompose_to_limbs_pub,
    provekit_common::FieldElement,
    std::collections::BTreeMap,
};

// ---------------------------------------------------------------------------
// Phase 1 output
// ---------------------------------------------------------------------------

/// Per-point scalar relation witness indices.
struct ScalarRelationInputs {
    s_lo: usize,
    s_hi: usize,
    s1:   usize,
    s2:   usize,
    neg1: usize,
    neg2: usize,
}

/// Per-point data collected during Phase 1 preprocessing.
struct PreprocessedData {
    all_skipped:       usize,
    merged_points:     Vec<ec_points::MergedGlvPoint>,
    scalar_rel_inputs: Vec<ScalarRelationInputs>,
    accum_inputs:      Vec<(Limbs, Limbs, usize)>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Unified multi-point MSM with per-limb I/O.
///
/// Point coordinates are provided as limbs (stride `2*num_limbs + 1` per
/// point). For native curves `num_limbs=1`, so each "limb" is the full
/// coordinate witness. Output coordinates are constrained per-limb.
pub(super) fn process_multi_point<E: EcOps>(
    compiler: &mut NoirToR1CSCompiler,
    point_wits: &[usize],
    scalar_wits: &[usize],
    outputs: &MsmLimbedOutputs,
    n_points: usize,
    num_limbs: usize,
    limb_bits: u32,
    window_size: usize,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    curve: &impl Curve,
) {
    let one = compiler.witness_one();
    let zero_witness = add_constant_witness(compiler, FieldElement::ZERO);

    // Generator as limbs — avoids truncation when generator coords > BN254_Fr
    let gen_x_fe_limbs = decompose_to_limbs_pub(&curve.generator().0, limb_bits, num_limbs);
    let gen_y_fe_limbs = decompose_to_limbs_pub(&curve.generator().1, limb_bits, num_limbs);
    let gen_x_limb_wits: Vec<usize> = gen_x_fe_limbs
        .iter()
        .map(|&v| add_constant_witness(compiler, v))
        .collect();
    let gen_y_limb_wits: Vec<usize> = gen_y_fe_limbs
        .iter()
        .map(|&v| add_constant_witness(compiler, v))
        .collect();

    // Build params once for all operations
    let params = MultiLimbParams::for_field_modulus(num_limbs, limb_bits, curve);
    // Offset point as limbs for accumulation
    let offset_x_values = curve.offset_x_limbs(limb_bits, num_limbs);
    let offset_y_values = curve.offset_y_limbs(limb_bits, num_limbs);

    // Phase 1: Per-point preprocessing
    let data = preprocess_points::<E>(
        compiler,
        range_checks,
        &params,
        point_wits,
        scalar_wits,
        &gen_x_limb_wits,
        &gen_y_limb_wits,
        zero_witness,
        one,
        n_points,
        num_limbs,
        limb_bits,
        curve,
    );

    // Phase 2: Per-point scalar mul verification
    verify_scalar_muls::<E>(
        compiler,
        range_checks,
        &params,
        &data.merged_points,
        &offset_x_values,
        &offset_y_values,
        window_size,
        num_limbs,
        limb_bits,
        curve,
    );

    // Phase 3: Per-point scalar relations
    for sr in &data.scalar_rel_inputs {
        scalar_relation::verify_scalar_relation(
            compiler,
            range_checks,
            sr.s_lo,
            sr.s_hi,
            sr.s1,
            sr.s2,
            sr.neg1,
            sr.neg2,
            curve,
        );
    }

    // Phase 4: Accumulation + output constraining
    accumulate_and_constrain_outputs::<E>(
        compiler,
        range_checks,
        &params,
        &data.accum_inputs,
        outputs,
        data.all_skipped,
        &offset_x_values,
        &offset_y_values,
        zero_witness,
        num_limbs,
        limb_bits,
        curve,
    );
}

// ---------------------------------------------------------------------------
// Phase 1: Per-point preprocessing
// ---------------------------------------------------------------------------

/// Sanitizes each point, verifies on-curve, decomposes scalars (FakeGLV +
/// signed bits), and conditionally negates y-coordinates.
#[allow(clippy::too_many_arguments)]
fn preprocess_points<E: EcOps>(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    params: &MultiLimbParams,
    point_wits: &[usize],
    scalar_wits: &[usize],
    gen_x_limb_wits: &[usize],
    gen_y_limb_wits: &[usize],
    zero_witness: usize,
    one: usize,
    n_points: usize,
    num_limbs: usize,
    limb_bits: u32,
    curve: &impl Curve,
) -> PreprocessedData {
    let stride = 2 * num_limbs + 1;
    let mut all_skipped: Option<usize> = None;
    let mut merged_points: Vec<ec_points::MergedGlvPoint> = Vec::new();
    let mut scalar_rel_inputs: Vec<ScalarRelationInputs> = Vec::new();
    let mut accum_inputs: Vec<(Limbs, Limbs, usize)> = Vec::new();

    for i in 0..n_points {
        // Extract point limbs and inf flag from limbed layout
        let base = i * stride;
        let mut px_limbs = Limbs::new(num_limbs);
        let mut py_limbs = Limbs::new(num_limbs);
        for j in 0..num_limbs {
            px_limbs[j] = point_wits[base + j];
            py_limbs[j] = point_wits[base + num_limbs + j];
            // Native (num_limbs=1): coordinates are native field elements,
            // no range check needed.  Non-native: range-check each limb.
            if num_limbs > 1 {
                range_checks.entry(limb_bits).or_default().push(px_limbs[j]);
                range_checks.entry(limb_bits).or_default().push(py_limbs[j]);
            }
        }
        let inf_flag = point_wits[base + 2 * num_limbs];

        // Sanitize at the limb level — per-limb select between input and generator
        let san = sanitize_point_scalar_multi_limb(
            compiler,
            px_limbs,
            py_limbs,
            scalar_wits[2 * i],
            scalar_wits[2 * i + 1],
            inf_flag,
            gen_x_limb_wits,
            gen_y_limb_wits,
            zero_witness,
            one,
        );

        // Track all_skipped
        all_skipped = Some(match all_skipped {
            None => san.is_skip,
            Some(prev) => compiler.add_product(prev, san.is_skip),
        });

        // EcScalarMulHint with multi-limb inputs/outputs
        let (rx, ry) = emit_ec_scalar_mul_hint_and_sanitize_multi_limb(
            compiler,
            &san,
            gen_x_limb_wits,
            gen_y_limb_wits,
            num_limbs,
            limb_bits,
            range_checks,
            curve,
        );

        let px = san.px_limbs;
        let py = san.py_limbs;

        // On-curve checks via MultiLimbOps (statically dispatched via E)
        {
            let mut ops = MultiLimbOps::<E>::new(&mut *compiler, &mut *range_checks, params);
            ops.verify_on_curve(px, py);
            ops.verify_on_curve(rx, ry);
        }

        // FakeGLV, bit decomposition, y-negation (via MultiLimbOps)
        let (s1_witness, s2_witness, neg1_witness, neg2_witness);
        let (py_effective, ry_effective, s1_bits, s2_bits, s1_skew, s2_skew);
        {
            let mut ops = MultiLimbOps::<E>::new(&mut *compiler, &mut *range_checks, params);

            // FakeGLVHint → |s1|, |s2|, neg1, neg2
            (s1_witness, s2_witness, neg1_witness, neg2_witness) =
                emit_fakeglv_hint(ops.compiler, san.s_lo, san.s_hi, curve);

            // Signed-bit decomposition of |s1|, |s2|
            let half_bits = curve.glv_half_bits() as usize;
            (s1_bits, s1_skew) = super::decompose_signed_bits(ops.compiler, s1_witness, half_bits);
            (s2_bits, s2_skew) = super::decompose_signed_bits(ops.compiler, s2_witness, half_bits);

            // Conditionally negate y-coordinates
            let neg_py = ops.negate(py);
            let neg_ry = ops.negate(ry);
            py_effective = ops.select(neg1_witness, py, neg_py);
            ry_effective = ops.select(neg2_witness, ry, neg_ry);
        }

        merged_points.push(ec_points::MergedGlvPoint {
            px,
            py: py_effective,
            s1_bits,
            s1_skew,
            rx,
            ry: ry_effective,
            s2_bits,
            s2_skew,
        });

        scalar_rel_inputs.push(ScalarRelationInputs {
            s_lo: san.s_lo,
            s_hi: san.s_hi,
            s1:   s1_witness,
            s2:   s2_witness,
            neg1: neg1_witness,
            neg2: neg2_witness,
        });
        accum_inputs.push((rx, ry, san.is_skip));
    }

    PreprocessedData {
        all_skipped: all_skipped.expect("MSM must have at least one point"),
        merged_points,
        scalar_rel_inputs,
        accum_inputs,
    }
}

// ---------------------------------------------------------------------------
// Phase 2: Per-point scalar mul verification
// ---------------------------------------------------------------------------

/// Each point gets its own accumulator and identity check. This ensures
/// per-point soundness: b_i * (R_i - scalar_i * P_i) = O with b_i ≠ 0
/// implies R_i = scalar_i * P_i for each point independently.
#[allow(clippy::too_many_arguments)]
fn verify_scalar_muls<E: EcOps>(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    params: &MultiLimbParams,
    merged_points: &[ec_points::MergedGlvPoint],
    offset_x_values: &[FieldElement],
    offset_y_values: &[FieldElement],
    window_size: usize,
    num_limbs: usize,
    limb_bits: u32,
    curve: &impl Curve,
) {
    let half_bits = curve.glv_half_bits() as usize;
    let mut ops = MultiLimbOps::<E>::new(&mut *compiler, &mut *range_checks, params);

    // Precompute the expected accumulated offset (same for all points)
    let glv_num_windows = (half_bits + window_size - 1) / window_size;
    let glv_n_doublings = glv_num_windows * window_size;
    let (acc_off_x_raw, acc_off_y_raw) = curve.accumulated_offset(glv_n_doublings);
    let acc_off_x_values = decompose_to_limbs_pub(&acc_off_x_raw, limb_bits, num_limbs);
    let acc_off_y_values = decompose_to_limbs_pub(&acc_off_y_raw, limb_bits, num_limbs);

    for pt in merged_points {
        let offset_x = ops.constant_limbs(offset_x_values);
        let offset_y = ops.constant_limbs(offset_y_values);

        let glv_acc = ec_points::scalar_mul_merged_glv(
            &mut ops,
            std::slice::from_ref(pt),
            window_size,
            offset_x,
            offset_y,
        );

        // Per-point identity check
        for j in 0..num_limbs {
            constrain_to_constant(ops.compiler, glv_acc.0[j], acc_off_x_values[j]);
            constrain_to_constant(ops.compiler, glv_acc.1[j], acc_off_y_values[j]);
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 4: Accumulation + output constraining
// ---------------------------------------------------------------------------

/// Accumulates per-point scalar-mul results, subtracts the offset, and
/// constrains the final coordinates to the output witnesses.
#[allow(clippy::too_many_arguments)]
fn accumulate_and_constrain_outputs<E: EcOps>(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    params: &MultiLimbParams,
    accum_inputs: &[(Limbs, Limbs, usize)],
    outputs: &MsmLimbedOutputs,
    all_skipped: usize,
    offset_x_values: &[FieldElement],
    offset_y_values: &[FieldElement],
    zero_witness: usize,
    num_limbs: usize,
    limb_bits: u32,
    curve: &impl Curve,
) {
    let mut ops = MultiLimbOps::<E>::new(&mut *compiler, &mut *range_checks, params);
    let mut acc_x = ops.constant_limbs(offset_x_values);
    let mut acc_y = ops.constant_limbs(offset_y_values);

    for &(rx, ry, is_skip) in accum_inputs {
        let (cand_x, cand_y) = ops.point_add(acc_x, acc_y, rx, ry);
        let (new_acc_x, new_acc_y) =
            ops.point_select_unchecked(is_skip, (cand_x, cand_y), (acc_x, acc_y));
        acc_x = new_acc_x;
        acc_y = new_acc_y;
    }

    // Offset subtraction
    let neg_offset_y_raw =
        curve::negate_field_element(&curve.offset_point().1, &curve.field_modulus_p());
    let neg_offset_y_values = curve::decompose_to_limbs(&neg_offset_y_raw, limb_bits, num_limbs);

    let gen_x_limb_values = curve.generator_x_limbs(limb_bits, num_limbs);
    let neg_gen_y_raw = curve::negate_field_element(&curve.generator().1, &curve.field_modulus_p());
    let neg_gen_y_values = curve::decompose_to_limbs(&neg_gen_y_raw, limb_bits, num_limbs);

    let sub_x = {
        let off_x = ops.constant_limbs(offset_x_values);
        let g_x = ops.constant_limbs(&gen_x_limb_values);
        ops.select(all_skipped, off_x, g_x)
    };
    let sub_y = {
        let neg_off_y = ops.constant_limbs(&neg_offset_y_values);
        let neg_g_y = ops.constant_limbs(&neg_gen_y_values);
        ops.select(all_skipped, neg_off_y, neg_g_y)
    };

    let (result_x, result_y) = ops.point_add(acc_x, acc_y, sub_x, sub_y);
    let compiler = ops.compiler;

    // Output constraining — per-limb for all curves
    for j in 0..num_limbs {
        let masked_x = select_witness(compiler, all_skipped, result_x[j], zero_witness);
        let masked_y = select_witness(compiler, all_skipped, result_y[j], zero_witness);
        constrain_equal(compiler, outputs.out_x_limbs[j], masked_x);
        constrain_equal(compiler, outputs.out_y_limbs[j], masked_y);
    }
    constrain_equal(compiler, outputs.out_inf, all_skipped);
}
