//! Non-native (generic multi-limb) MSM path.
//!
//! Used when `!curve.is_native_field()` — uses `MultiLimbOps` for all EC
//! arithmetic with configurable limb width.
//!
//! Multi-point MSM uses merged doublings: all points share a single set of
//! `w` doublings per window, saving `w × (n_points - 1)` doublings per window.

use {
    super::{
        curve, ec_points, emit_ec_scalar_mul_hint_and_sanitize, emit_fakeglv_hint,
        multi_limb_ops::{MultiLimbOps, MultiLimbParams},
        sanitize_point_scalar, scalar_relation, Limbs,
    },
    crate::{
        constraint_helpers::{
            add_constant_witness, constrain_equal, constrain_to_constant, select_witness,
        },
        digits::{add_digital_decomposition, DigitalDecompositionWitnessesBuilder},
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::{AdditiveGroup, Field},
    curve::{decompose_to_limbs as decompose_to_limbs_pub, CurveParams},
    provekit_common::{witness::SumTerm, FieldElement},
    std::collections::BTreeMap,
};

/// Multi-point non-native MSM with merged-loop optimization.
///
/// All points share a single set of doublings per window, saving
/// `w × (n_points - 1)` doublings per window compared to separate loops.
pub(super) fn process_multi_point_non_native<'a>(
    mut compiler: &'a mut NoirToR1CSCompiler,
    point_wits: &[usize],
    scalar_wits: &[usize],
    outputs: (usize, usize, usize),
    n_points: usize,
    num_limbs: usize,
    limb_bits: u32,
    window_size: usize,
    mut range_checks: &'a mut BTreeMap<u32, Vec<usize>>,
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

    // Build params once for all multi-limb ops
    let params = MultiLimbParams::for_field_modulus(num_limbs, limb_bits, curve);
    let b_limb_values = curve::decompose_to_limbs(&curve.curve_b, limb_bits, num_limbs);

    // Offset point as limbs for accumulation
    let offset_x_values = curve.offset_x_limbs(limb_bits, num_limbs);
    let offset_y_values = curve.offset_y_limbs(limb_bits, num_limbs);

    // Track all_skipped = product of all is_skip flags
    let mut all_skipped: Option<usize> = None;
    let mut merged_points: Vec<ec_points::MergedGlvPoint> = Vec::new();
    let mut scalar_rel_inputs: Vec<(usize, usize, usize, usize, usize, usize)> = Vec::new();
    let mut accum_inputs: Vec<(Limbs, Limbs, usize)> = Vec::new();

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

        // Track all_skipped
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

        // Decompose points to limbs
        let (px, py) =
            decompose_point_to_limbs(compiler, san.px, san.py, num_limbs, limb_bits, range_checks);
        let (rx, ry) = decompose_point_to_limbs(
            compiler,
            sanitized_rx,
            sanitized_ry,
            num_limbs,
            limb_bits,
            range_checks,
        );

        // On-curve checks: use hint-verified for multi-limb, generic for single-limb
        if num_limbs >= 2 {
            ec_points::verify_on_curve_non_native(compiler, range_checks, px, py, &params);
            ec_points::verify_on_curve_non_native(compiler, range_checks, rx, ry, &params);
        } else {
            let mut ops = MultiLimbOps {
                compiler,
                range_checks,
                params: &params,
            };
            verify_on_curve(&mut ops, px, py, &b_limb_values, num_limbs);
            verify_on_curve(&mut ops, rx, ry, &b_limb_values, num_limbs);
            compiler = ops.compiler;
            range_checks = ops.range_checks;
        }

        // FakeGLV, bit decomposition, y-negation (via MultiLimbOps)
        let (s1_witness, s2_witness, neg1_witness, neg2_witness);
        let (py_effective, ry_effective, s1_bits, s2_bits, s1_skew, s2_skew);
        {
            let mut ops = MultiLimbOps {
                compiler,
                range_checks,
                params: &params,
            };

            // FakeGLVHint → |s1|, |s2|, neg1, neg2
            (s1_witness, s2_witness, neg1_witness, neg2_witness) =
                emit_fakeglv_hint(ops.compiler, san.s_lo, san.s_hi, curve);

            // Signed-bit decomposition of |s1|, |s2| — produces signed digits
            // d_i = 2*b_i - 1 ∈ {-1, +1} with skew correction, matching the
            // native path's wNAF approach.
            let half_bits = curve.glv_half_bits() as usize;
            (s1_bits, s1_skew) = super::decompose_signed_bits(ops.compiler, s1_witness, half_bits);
            (s2_bits, s2_skew) = super::decompose_signed_bits(ops.compiler, s2_witness, half_bits);

            // Conditionally negate y-coordinates
            let neg_py = ops.negate(py);
            let neg_ry = ops.negate(ry);
            py_effective = ops.select(neg1_witness, py, neg_py);
            ry_effective = ops.select(neg2_witness, ry, neg_ry);

            compiler = ops.compiler;
            range_checks = ops.range_checks;
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

        scalar_rel_inputs.push((
            san.s_lo,
            san.s_hi,
            s1_witness,
            s2_witness,
            neg1_witness,
            neg2_witness,
        ));
        accum_inputs.push((rx, ry, san.is_skip));
    }

    // Phase 2: Merged scalar mul verification (shared doublings across all points)
    let half_bits = curve.glv_half_bits() as usize;
    let glv_acc;
    {
        let mut ops = MultiLimbOps {
            compiler,
            range_checks,
            params: &params,
        };
        let offset_x = ops.constant_limbs(&offset_x_values);
        let offset_y = ops.constant_limbs(&offset_y_values);

        glv_acc = ec_points::scalar_mul_merged_glv(
            &mut ops,
            &merged_points,
            window_size,
            offset_x,
            offset_y,
        );

        // Identity check: acc should equal accumulated offset
        let glv_num_windows = (half_bits + window_size - 1) / window_size;
        let glv_n_doublings = glv_num_windows * window_size;
        let (acc_off_x_raw, acc_off_y_raw) = curve.accumulated_offset(glv_n_doublings);

        let acc_off_x_values = decompose_to_limbs_pub(&acc_off_x_raw, limb_bits, num_limbs);
        let acc_off_y_values = decompose_to_limbs_pub(&acc_off_y_raw, limb_bits, num_limbs);
        for i in 0..num_limbs {
            constrain_to_constant(ops.compiler, glv_acc.0[i], acc_off_x_values[i]);
            constrain_to_constant(ops.compiler, glv_acc.1[i], acc_off_y_values[i]);
        }

        compiler = ops.compiler;
        range_checks = ops.range_checks;
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

    // Phase 4: Accumulation (offset-based, same as before)
    let all_skipped = all_skipped.expect("MSM must have at least one point");

    let mut ops = MultiLimbOps {
        compiler,
        range_checks,
        params: &params,
    };
    let mut acc_x = ops.constant_limbs(&offset_x_values);
    let mut acc_y = ops.constant_limbs(&offset_y_values);

    for &(rx, ry, is_skip) in &accum_inputs {
        let (cand_x, cand_y) = ec_points::point_add_dispatch(&mut ops, acc_x, acc_y, rx, ry);
        let (new_acc_x, new_acc_y) =
            ec_points::point_select_unchecked(&mut ops, is_skip, (cand_x, cand_y), (acc_x, acc_y));
        acc_x = new_acc_x;
        acc_y = new_acc_y;
    }

    // Offset subtraction
    let neg_offset_y_raw =
        curve::negate_field_element(&curve.offset_point.1, &curve.field_modulus_p);
    let neg_offset_y_values = curve::decompose_to_limbs(&neg_offset_y_raw, limb_bits, num_limbs);

    let gen_x_limb_values = curve.generator_x_limbs(limb_bits, num_limbs);
    let neg_gen_y_raw = curve::negate_field_element(&curve.generator.1, &curve.field_modulus_p);
    let neg_gen_y_values = curve::decompose_to_limbs(&neg_gen_y_raw, limb_bits, num_limbs);

    let sub_x = {
        let off_x = ops.constant_limbs(&offset_x_values);
        let g_x = ops.constant_limbs(&gen_x_limb_values);
        ops.select(all_skipped, off_x, g_x)
    };
    let sub_y = {
        let neg_off_y = ops.constant_limbs(&neg_offset_y_values);
        let neg_g_y = ops.constant_limbs(&neg_gen_y_values);
        ops.select(all_skipped, neg_off_y, neg_g_y)
    };

    let (result_x, result_y) = ec_points::point_add_dispatch(&mut ops, acc_x, acc_y, sub_x, sub_y);
    compiler = ops.compiler;

    if num_limbs == 1 {
        let masked_result_x = select_witness(compiler, all_skipped, result_x[0], zero_witness);
        let masked_result_y = select_witness(compiler, all_skipped, result_y[0], zero_witness);
        constrain_equal(compiler, out_x, masked_result_x);
        constrain_equal(compiler, out_y, masked_result_y);
    } else {
        let recomposed_x = recompose_limbs(compiler, result_x.as_slice(), limb_bits);
        let recomposed_y = recompose_limbs(compiler, result_y.as_slice(), limb_bits);
        let masked_result_x = select_witness(compiler, all_skipped, recomposed_x, zero_witness);
        let masked_result_y = select_witness(compiler, all_skipped, recomposed_y, zero_witness);
        constrain_equal(compiler, out_x, masked_result_x);
        constrain_equal(compiler, out_y, masked_result_y);
    }
    constrain_equal(compiler, out_inf, all_skipped);
}

/// On-curve check: verifies y^2 = x^3 + a*x + b for a single point.
fn verify_on_curve(
    ops: &mut MultiLimbOps,
    x: Limbs,
    y: Limbs,
    b_limb_values: &[FieldElement],
    num_limbs: usize,
) {
    let y_sq = ops.mul(y, y);
    let x_sq = ops.mul(x, x);
    let x_cubed = ops.mul(x_sq, x);
    let a = ops.curve_a();
    let ax = ops.mul(a, x);
    let x3_plus_ax = ops.add(x_cubed, ax);
    let b = ops.constant_limbs(b_limb_values);
    let rhs = ops.add(x3_plus_ax, b);
    for i in 0..num_limbs {
        constrain_equal(ops.compiler, y_sq[i], rhs[i]);
    }
}

/// Decompose a point (px_witness, py_witness) into Limbs.
fn decompose_point_to_limbs(
    compiler: &mut NoirToR1CSCompiler,
    px_witness: usize,
    py_witness: usize,
    num_limbs: usize,
    limb_bits: u32,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) -> (Limbs, Limbs) {
    if num_limbs == 1 {
        (Limbs::single(px_witness), Limbs::single(py_witness))
    } else {
        let px_limbs =
            decompose_witness_to_limbs(compiler, px_witness, limb_bits, num_limbs, range_checks);
        let py_limbs =
            decompose_witness_to_limbs(compiler, py_witness, limb_bits, num_limbs, range_checks);
        (px_limbs, py_limbs)
    }
}

/// Decompose a single witness into `num_limbs` limbs using digital
/// decomposition.
fn decompose_witness_to_limbs(
    compiler: &mut NoirToR1CSCompiler,
    witness: usize,
    limb_bits: u32,
    num_limbs: usize,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) -> Limbs {
    let log_bases = vec![limb_bits as usize; num_limbs];
    let dd = add_digital_decomposition(compiler, log_bases, vec![witness]);
    let mut limbs = Limbs::new(num_limbs);
    for i in 0..num_limbs {
        limbs[i] = dd.get_digit_witness_index(i, 0);
        // Range-check each decomposed limb to [0, 2^limb_bits).
        // add_digital_decomposition constrains the recomposition but does
        // NOT range-check individual digits.
        range_checks.entry(limb_bits).or_default().push(limbs[i]);
    }
    limbs
}

/// Recompose limbs back into a single witness: val = Σ limb\[i\] *
/// 2^(i*limb_bits)
fn recompose_limbs(compiler: &mut NoirToR1CSCompiler, limbs: &[usize], limb_bits: u32) -> usize {
    let terms: Vec<SumTerm> = limbs
        .iter()
        .enumerate()
        .map(|(i, &limb)| {
            let coeff = FieldElement::from(2u64).pow([(i as u64) * (limb_bits as u64)]);
            SumTerm(Some(coeff), limb)
        })
        .collect();
    compiler.add_sum(terms)
}

// `decompose_half_scalar_bits` replaced by `super::decompose_signed_bits`
// which produces signed digits with skew correction, halving lookup tables.
