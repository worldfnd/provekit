//! Non-native (generic multi-limb) MSM path.
//!
//! Used when `!curve.is_native_field()` — uses `MultiLimbOps` for all EC
//! arithmetic with configurable limb width.

use {
    super::{
        add_constant_witness, constrain_equal, constrain_to_constant, curve, ec_points,
        emit_ec_scalar_mul_hint_and_sanitize, emit_fakeglv_hint, sanitize_point_scalar,
        scalar_relation, select_witness, FieldOps, Limbs,
    },
    crate::{
        digits::{add_digital_decomposition, DigitalDecompositionWitnessesBuilder},
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::{AdditiveGroup, Field},
    curve::{decompose_to_limbs as decompose_to_limbs_pub, CurveParams},
    multi_limb_ops::{MultiLimbOps, MultiLimbParams},
    provekit_common::{
        witness::SumTerm,
        FieldElement,
    },
    std::collections::BTreeMap,
    super::multi_limb_ops,
};

/// Build `MultiLimbParams` for a given runtime `num_limbs`.
pub(super) fn build_params(
    num_limbs: usize,
    limb_bits: u32,
    curve: &CurveParams,
) -> MultiLimbParams {
    let is_native = curve.is_native_field();
    let two_pow_w = FieldElement::from(2u64).pow([limb_bits as u64]);
    let modulus_fe = if !is_native {
        Some(curve.p_native_fe())
    } else {
        None
    };
    MultiLimbParams {
        num_limbs,
        limb_bits,
        p_limbs: curve.p_limbs(limb_bits, num_limbs),
        p_minus_1_limbs: curve.p_minus_1_limbs(limb_bits, num_limbs),
        two_pow_w,
        modulus_raw: curve.field_modulus_p,
        curve_a_limbs: curve.curve_a_limbs(limb_bits, num_limbs),
        is_native,
        modulus_fe,
    }
}

/// FakeGLV verification for a single point: verifies R = \[s\]P.
///
/// Decomposes s via half-GCD into sub-scalars (s1, s2) and verifies
/// \[s1\]P + \[s2\]R = O using interleaved windowed scalar mul with
/// half-width scalars.
///
/// Returns the mutable references back to the caller for continued use.
pub(super) fn verify_point_fakeglv<'a>(
    mut compiler: &'a mut NoirToR1CSCompiler,
    mut range_checks: &'a mut BTreeMap<u32, Vec<usize>>,
    px: Limbs,
    py: Limbs,
    rx: Limbs,
    ry: Limbs,
    s_lo: usize,
    s_hi: usize,
    num_limbs: usize,
    limb_bits: u32,
    window_size: usize,
    curve: &CurveParams,
) -> (
    &'a mut NoirToR1CSCompiler,
    &'a mut BTreeMap<u32, Vec<usize>>,
) {
    // --- Steps 1-4: On-curve checks, FakeGLV decomposition, and GLV scalar mul
    // ---
    let (s1_witness, s2_witness, neg1_witness, neg2_witness);
    {
        let params = build_params(num_limbs, limb_bits, curve);
        let mut ops = MultiLimbOps {
            compiler,
            range_checks,
            params: &params,
        };

        // Step 1: On-curve checks for P and R
        let b_limb_values = curve::decompose_to_limbs(&curve.curve_b, limb_bits, num_limbs);
        verify_on_curve(&mut ops, px, py, &b_limb_values, num_limbs);
        verify_on_curve(&mut ops, rx, ry, &b_limb_values, num_limbs);

        // Step 2: FakeGLVHint → |s1|, |s2|, neg1, neg2
        (s1_witness, s2_witness, neg1_witness, neg2_witness) =
            emit_fakeglv_hint(ops.compiler, s_lo, s_hi, curve);

        // Step 3: Decompose |s1|, |s2| into half_bits bits each
        let half_bits = curve.glv_half_bits() as usize;
        let s1_bits = decompose_half_scalar_bits(ops.compiler, s1_witness, half_bits);
        let s2_bits = decompose_half_scalar_bits(ops.compiler, s2_witness, half_bits);

        // Step 4: Conditionally negate P.y and R.y + GLV scalar mul + identity
        // check

        // Compute negated y-coordinates: neg_y = 0 - y (mod p)
        let neg_py = ops.negate(py);
        let neg_ry = ops.negate(ry);

        // Select: if neg1=1, use neg_py; else use py
        // neg1 and neg2 are constrained to be boolean by ops.select internally.
        let py_effective = ops.select(neg1_witness, py, neg_py);
        // Select: if neg2=1, use neg_ry; else use ry
        let ry_effective = ops.select(neg2_witness, ry, neg_ry);

        // GLV scalar mul
        let offset_x_values = curve.offset_x_limbs(limb_bits, num_limbs);
        let offset_y_values = curve.offset_y_limbs(limb_bits, num_limbs);
        let offset_x = ops.constant_limbs(&offset_x_values);
        let offset_y = ops.constant_limbs(&offset_y_values);

        let glv_acc = ec_points::scalar_mul_glv(
            &mut ops,
            px,
            py_effective,
            &s1_bits,
            rx,
            ry_effective,
            &s2_bits,
            window_size,
            offset_x,
            offset_y,
        );

        // Identity check: acc should equal [2^(num_windows * window_size)] *
        // offset_point
        let glv_num_windows = (half_bits + window_size - 1) / window_size;
        let glv_n_doublings = glv_num_windows * window_size;
        let (acc_off_x_raw, acc_off_y_raw) = curve.accumulated_offset(glv_n_doublings);

        // Identity check: hardcode expected limb values as R1CS coefficients
        let acc_off_x_values = decompose_to_limbs_pub(&acc_off_x_raw, limb_bits, num_limbs);
        let acc_off_y_values = decompose_to_limbs_pub(&acc_off_y_raw, limb_bits, num_limbs);
        for i in 0..num_limbs {
            constrain_to_constant(ops.compiler, glv_acc.0[i], acc_off_x_values[i]);
            constrain_to_constant(ops.compiler, glv_acc.1[i], acc_off_y_values[i]);
        }

        compiler = ops.compiler;
        range_checks = ops.range_checks;
    }

    // --- Step 5: Scalar relation verification ---
    scalar_relation::verify_scalar_relation(
        compiler,
        range_checks,
        s_lo,
        s_hi,
        s1_witness,
        s2_witness,
        neg1_witness,
        neg2_witness,
        curve,
    );

    (compiler, range_checks)
}

/// Multi-point non-native MSM with offset-based accumulation.
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

    // Build params once for all multi-limb ops in the multi-point path
    let params = build_params(num_limbs, limb_bits, curve);

    // Offset point as limbs for accumulation
    let offset_x_values = curve.offset_x_limbs(limb_bits, num_limbs);
    let offset_y_values = curve.offset_y_limbs(limb_bits, num_limbs);

    // Start accumulator at offset_point
    let mut ops = MultiLimbOps {
        compiler,
        range_checks,
        params: &params,
    };
    let mut acc_x = ops.constant_limbs(&offset_x_values);
    let mut acc_y = ops.constant_limbs(&offset_y_values);
    compiler = ops.compiler;
    range_checks = ops.range_checks;

    // Track all_skipped = product of all is_skip flags
    let mut all_skipped: Option<usize> = None;

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

        // Generic multi-limb path
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

        // Verify R_i = [s_i]P_i using FakeGLV (on sanitized values)
        (compiler, range_checks) = verify_point_fakeglv(
            compiler,
            range_checks,
            px,
            py,
            rx,
            ry,
            san.s_lo,
            san.s_hi,
            num_limbs,
            limb_bits,
            window_size,
            curve,
        );

        // Offset-based accumulation with conditional select
        let mut ops = MultiLimbOps {
            compiler,
            range_checks,
            params: &params,
        };
        let (cand_x, cand_y) = ec_points::point_add(&mut ops, acc_x, acc_y, rx, ry);
        let (new_acc_x, new_acc_y) = ec_points::point_select_unchecked(
            &mut ops,
            san.is_skip,
            (cand_x, cand_y),
            (acc_x, acc_y),
        );
        acc_x = new_acc_x;
        acc_y = new_acc_y;
        compiler = ops.compiler;
        range_checks = ops.range_checks;
    }

    let all_skipped = all_skipped.expect("MSM must have at least one point");

    // Generic multi-limb offset subtraction
    let neg_offset_y_raw =
        curve::negate_field_element(&curve.offset_point.1, &curve.field_modulus_p);
    let neg_offset_y_values = curve::decompose_to_limbs(&neg_offset_y_raw, limb_bits, num_limbs);

    let gen_x_limb_values = curve.generator_x_limbs(limb_bits, num_limbs);
    let neg_gen_y_raw = curve::negate_field_element(&curve.generator.1, &curve.field_modulus_p);
    let neg_gen_y_values = curve::decompose_to_limbs(&neg_gen_y_raw, limb_bits, num_limbs);

    let mut ops = MultiLimbOps {
        compiler,
        range_checks,
        params: &params,
    };

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

    let (result_x, result_y) = ec_points::point_add(&mut ops, acc_x, acc_y, sub_x, sub_y);
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
pub(super) fn decompose_point_to_limbs(
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

/// Decomposes a half-scalar witness into `half_bits` bit witnesses (LSB first).
fn decompose_half_scalar_bits(
    compiler: &mut NoirToR1CSCompiler,
    scalar: usize,
    half_bits: usize,
) -> Vec<usize> {
    let log_bases = vec![1usize; half_bits];
    let dd = add_digital_decomposition(compiler, log_bases, vec![scalar]);
    let mut bits = Vec::with_capacity(half_bits);
    for bit_idx in 0..half_bits {
        bits.push(dd.get_digit_witness_index(bit_idx, 0));
    }
    bits
}
