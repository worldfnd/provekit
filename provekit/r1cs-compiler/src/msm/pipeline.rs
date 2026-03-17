//! Unified MSM pipeline for all curves, generic over `E: EcOps`.
//!
//! Orchestrates 4 phases: preprocessing, scalar mul verification,
//! scalar relations, and accumulation.

use {
    super::{
        curve::{self, Curve},
        ec_points::{self, EcOps},
        multi_limb_ops::{EcFieldParams, MultiLimbOps},
        sanitize::{
            emit_ec_scalar_mul_hint_and_sanitize_multi_limb, emit_fakeglv_hint,
            sanitize_point_scalar_multi_limb,
        },
        scalar_relation, EcPoint, Limbs, MsmConfig, MsmLimbedOutputs,
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

/// EC-aware `MultiLimbOps` with both field (`E::Field`) and EC (`E`) ops
/// available.
type EcOpsCtx<'a, 'p, E> = MultiLimbOps<'a, 'p, <E as EcOps>::Field, E, EcFieldParams>;

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
    accum_inputs:      Vec<(EcPoint, usize)>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Unified multi-point MSM with per-limb I/O.
pub(super) fn process_multi_point<E: EcOps>(
    compiler: &mut NoirToR1CSCompiler,
    point_wits: &[usize],
    scalar_wits: &[usize],
    outputs: &MsmLimbedOutputs,
    n_points: usize,
    config: &MsmConfig,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    curve: &impl Curve,
) {
    let num_limbs = config.num_limbs;
    let limb_bits = config.limb_bits;
    let one = compiler.witness_one();
    let zero_witness = add_constant_witness(compiler, FieldElement::ZERO);

    // Generator as limbs
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
    let params = EcFieldParams::for_field_modulus(num_limbs, limb_bits, curve);
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
        config,
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
        config,
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
        config,
        curve,
    );
}

// ---------------------------------------------------------------------------
// Phase 1: Per-point preprocessing
// ---------------------------------------------------------------------------

/// Per-point preprocessing: sanitize, on-curve check, scalar decomposition,
/// y-negation.
fn preprocess_points<E: EcOps>(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    params: &EcFieldParams,
    point_wits: &[usize],
    scalar_wits: &[usize],
    gen_x_limb_wits: &[usize],
    gen_y_limb_wits: &[usize],
    zero_witness: usize,
    one: usize,
    n_points: usize,
    config: &MsmConfig,
    curve: &impl Curve,
) -> PreprocessedData {
    let num_limbs = config.num_limbs;
    let limb_bits = config.limb_bits;
    let stride = 2 * num_limbs + 1;
    let mut all_skipped: Option<usize> = None;
    let mut merged_points: Vec<ec_points::MergedGlvPoint> = Vec::new();
    let mut scalar_rel_inputs: Vec<ScalarRelationInputs> = Vec::new();
    let mut accum_inputs: Vec<(EcPoint, usize)> = Vec::new();

    for i in 0..n_points {
        // Extract point limbs and inf flag from limbed layout
        let base = i * stride;
        let mut px_limbs = Limbs::new();
        let mut py_limbs = Limbs::new();
        for j in 0..num_limbs {
            let px_j = point_wits[base + j];
            let py_j = point_wits[base + num_limbs + j];
            px_limbs.push(px_j);
            py_limbs.push(py_j);
            // Non-native: range-check each limb
            if num_limbs > 1 {
                range_checks.entry(limb_bits).or_default().push(px_j);
                range_checks.entry(limb_bits).or_default().push(py_j);
            }
        }
        let inf_flag = point_wits[base + 2 * num_limbs];

        // Sanitize point-scalar pair
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
            limb_bits,
            range_checks,
            curve,
        );

        let p = EcPoint {
            x: san.px_limbs,
            y: san.py_limbs,
        };
        let r = EcPoint { x: rx, y: ry };

        // On-curve checks
        {
            let mut ops = EcOpsCtx::<E>::new(&mut *compiler, &mut *range_checks, params);
            ops.verify_on_curve(p);
            ops.verify_on_curve(r);
        }

        // FakeGLV decomposition and y-negation
        let (s1_witness, s2_witness, neg1_witness, neg2_witness);
        let (py_effective, ry_effective, s1_bits, s2_bits, s1_skew, s2_skew);
        {
            let mut ops = EcOpsCtx::<E>::new(&mut *compiler, &mut *range_checks, params);

            // FakeGLVHint → |s1|, |s2|, neg1, neg2
            (s1_witness, s2_witness, neg1_witness, neg2_witness) =
                emit_fakeglv_hint(ops.compiler, san.s_lo, san.s_hi, curve);

            // Signed-bit decomposition of |s1|, |s2|
            let half_bits = curve.glv_half_bits() as usize;
            (s1_bits, s1_skew) = super::decompose_signed_bits(ops.compiler, s1_witness, half_bits);
            (s2_bits, s2_skew) = super::decompose_signed_bits(ops.compiler, s2_witness, half_bits);

            // Conditionally negate y-coordinates
            let neg_py = ops.negate(p.y);
            let neg_ry = ops.negate(r.y);
            py_effective = ops.select(neg1_witness, p.y, neg_py);
            ry_effective = ops.select(neg2_witness, r.y, neg_ry);
        }

        merged_points.push(ec_points::MergedGlvPoint {
            p: EcPoint {
                x: p.x,
                y: py_effective,
            },
            s1_bits,
            s1_skew,
            r: EcPoint {
                x: r.x,
                y: ry_effective,
            },
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
        accum_inputs.push((r, san.is_skip));
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

/// Per-point scalar mul verification with independent identity checks.
fn verify_scalar_muls<E: EcOps>(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    params: &EcFieldParams,
    merged_points: &[ec_points::MergedGlvPoint],
    offset_x_values: &[FieldElement],
    offset_y_values: &[FieldElement],
    config: &MsmConfig,
    curve: &impl Curve,
) {
    let num_limbs = config.num_limbs;
    let limb_bits = config.limb_bits;
    let window_size = config.window_size;
    let half_bits = curve.glv_half_bits() as usize;
    let mut ops = EcOpsCtx::<E>::new(&mut *compiler, &mut *range_checks, params);

    // Expected accumulated offset
    let glv_num_windows = (half_bits + window_size - 1) / window_size;
    let glv_n_doublings = glv_num_windows * window_size;
    let (acc_off_x_raw, acc_off_y_raw) = curve.accumulated_offset(glv_n_doublings);
    let acc_off_x_values = decompose_to_limbs_pub(&acc_off_x_raw, limb_bits, num_limbs);
    let acc_off_y_values = decompose_to_limbs_pub(&acc_off_y_raw, limb_bits, num_limbs);

    // Allocate offset once
    let offset = EcPoint {
        x: ops.constant_limbs(offset_x_values),
        y: ops.constant_limbs(offset_y_values),
    };

    for pt in merged_points {
        let glv_acc = ec_points::scalar_mul_merged_glv(
            &mut ops,
            std::slice::from_ref(pt),
            window_size,
            offset,
        );

        // Per-point identity check
        for j in 0..num_limbs {
            constrain_to_constant(ops.compiler, glv_acc.x[j], acc_off_x_values[j]);
            constrain_to_constant(ops.compiler, glv_acc.y[j], acc_off_y_values[j]);
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 4: Accumulation + output constraining
// ---------------------------------------------------------------------------

/// Accumulates per-point scalar-mul results, subtracts the offset, and
/// constrains the final coordinates to the output witnesses.
fn accumulate_and_constrain_outputs<E: EcOps>(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    params: &EcFieldParams,
    accum_inputs: &[(EcPoint, usize)],
    outputs: &MsmLimbedOutputs,
    all_skipped: usize,
    offset_x_values: &[FieldElement],
    offset_y_values: &[FieldElement],
    zero_witness: usize,
    config: &MsmConfig,
    curve: &impl Curve,
) {
    let num_limbs = config.num_limbs;
    let limb_bits = config.limb_bits;
    let mut ops = EcOpsCtx::<E>::new(&mut *compiler, &mut *range_checks, params);
    // Allocate offset limbs once
    let offset_x = ops.constant_limbs(offset_x_values);
    let offset_y = ops.constant_limbs(offset_y_values);
    let mut acc = EcPoint {
        x: offset_x,
        y: offset_y,
    };

    for &(r, is_skip) in accum_inputs {
        let cand = ops.point_add(acc, r);
        acc = ops.point_select_unchecked(is_skip, cand, acc);
    }

    // Offset subtraction
    let neg_offset_y_raw =
        curve::negate_field_element(&curve.offset_point().1, &curve.field_modulus_p());
    let neg_offset_y_values = curve::decompose_to_limbs(&neg_offset_y_raw, limb_bits, num_limbs);

    let gen_x_limb_values = curve.generator_x_limbs(limb_bits, num_limbs);
    let neg_gen_y_raw = curve::negate_field_element(&curve.generator().1, &curve.field_modulus_p());
    let neg_gen_y_values = curve::decompose_to_limbs(&neg_gen_y_raw, limb_bits, num_limbs);

    let sub_pt = EcPoint {
        x: {
            let g_x = ops.constant_limbs(&gen_x_limb_values);
            ops.select(all_skipped, offset_x, g_x)
        },
        y: {
            let neg_off_y = ops.constant_limbs(&neg_offset_y_values);
            let neg_g_y = ops.constant_limbs(&neg_gen_y_values);
            ops.select_unchecked(all_skipped, neg_off_y, neg_g_y)
        },
    };

    let result = ops.point_add(acc, sub_pt);
    let compiler = ops.compiler;

    // Output constraining
    for j in 0..num_limbs {
        let masked_x = select_witness(compiler, all_skipped, result.x[j], zero_witness);
        let masked_y = select_witness(compiler, all_skipped, result.y[j], zero_witness);
        constrain_equal(compiler, outputs.out_x_limbs[j], masked_x);
        constrain_equal(compiler, outputs.out_y_limbs[j], masked_y);
    }
    constrain_equal(compiler, outputs.out_inf, all_skipped);
}
