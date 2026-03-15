//! Non-native hint-verified EC operations (multi-limb schoolbook).
//!
//! Each EC op allocates a prover hint and verifies it via schoolbook
//! column equations, avoiding step-by-step field inversions.

use {
    crate::{
        msm::{
            ceil_log2,
            multi_limb_arith::{emit_schoolbook_column_equations, less_than_p_check_multi},
            multi_limb_ops::MultiLimbParams,
            Limbs,
        },
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::{Field, PrimeField},
    provekit_common::{
        witness::{NonNativeEcOp, WitnessBuilder},
        FieldElement,
    },
    std::collections::BTreeMap,
};

/// Collect witness indices from `start..start+len`.
fn witness_range(start: usize, len: usize) -> Vec<usize> {
    (start..start + len).collect()
}

/// Allocate N×N product witnesses for `a\[i\]*b\[j\]`.
fn make_products(compiler: &mut NoirToR1CSCompiler, a: &[usize], b: &[usize]) -> Vec<Vec<usize>> {
    let n = a.len();
    debug_assert_eq!(n, b.len());
    let mut prods = vec![vec![0usize; n]; n];
    for i in 0..n {
        for j in 0..n {
            prods[i][j] = compiler.add_product(a[i], b[j]);
        }
    }
    prods
}

/// Allocate pinned constant witnesses from pre-decomposed `FieldElement` limbs.
fn allocate_pinned_constant_limbs(
    compiler: &mut NoirToR1CSCompiler,
    limb_values: &[FieldElement],
) -> Vec<usize> {
    use crate::msm::multi_limb_ops::allocate_pinned_constant;
    limb_values
        .iter()
        .map(|&val| allocate_pinned_constant(compiler, val))
        .collect()
}

/// Range-check limb witnesses at `limb_bits` and carry witnesses at
/// `carry_range_bits`.
fn range_check_limbs_and_carries(
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    limb_vecs: &[&[usize]],
    carry_vecs: &[&[usize]],
    limb_bits: u32,
    carry_range_bits: u32,
) {
    for limbs in limb_vecs {
        for &w in *limbs {
            range_checks.entry(limb_bits).or_default().push(w);
        }
    }
    for carries in carry_vecs {
        for &c in *carries {
            range_checks.entry(carry_range_bits).or_default().push(c);
        }
    }
}

/// Convert `Vec<usize>` to `Limbs` and do a less-than-p check.
fn less_than_p_check_vec(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    v: &[usize],
    params: &MultiLimbParams,
) {
    less_than_p_check_multi(
        compiler,
        range_checks,
        Limbs::from(v),
        &params.p_minus_1_limbs,
        params.two_pow_w,
        params.limb_bits,
    );
}

/// Compute carry range bits for hint-verified column equations.
fn carry_range_bits(limb_bits: u32, max_coeff_sum: u64, n: usize) -> u32 {
    let extra_bits = ceil_log2(max_coeff_sum * n as u64) + 1;
    limb_bits + extra_bits + 1
}

/// Soundness check: verify that merged column equations fit the native field.
fn check_column_equation_fits(limb_bits: u32, max_coeff_sum: u64, n: usize, op_name: &str) {
    let extra_bits = ceil_log2(max_coeff_sum * n as u64) + 1;
    let max_bits = 2 * limb_bits + extra_bits + 1;
    assert!(
        max_bits < FieldElement::MODULUS_BIT_SIZE,
        "{op_name} column equation overflow: limb_bits={limb_bits}, n={n}, needs {max_bits} bits",
    );
}

/// Hint-verified on-curve check: y² = x³ + ax + b (mod p).
pub fn verify_on_curve_non_native(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    px: Limbs,
    py: Limbs,
    params: &MultiLimbParams,
) {
    let n = params.num_limbs;
    assert!(n >= 2, "hint-verified on-curve check requires n >= 2");

    let a_is_zero = params.curve_a_raw.iter().all(|&v| v == 0);

    let max_coeff_sum: u64 = if a_is_zero {
        4 + 2 * n as u64
    } else {
        5 + 2 * n as u64
    };
    check_column_equation_fits(params.limb_bits, max_coeff_sum, n, "On-curve");

    // Allocate hint
    let os = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::NonNativeEcHint {
        output_start:    os,
        op:              NonNativeEcOp::OnCurve,
        inputs:          vec![px.as_slice().to_vec(), py.as_slice().to_vec()],
        curve_a:         params.curve_a_raw,
        curve_b:         params.curve_b_raw,
        field_modulus_p: params.modulus_raw,
        limb_bits:       params.limb_bits,
        num_limbs:       n as u32,
    });

    // Parse hint layout: [x_sq(N), q1_pos(N), q1_neg(N), c1(2N-2),
    //                      q2_pos(N), q2_neg(N), c2(2N-2)]
    // Total: 9N-4
    let x_sq = witness_range(os, n);
    let q1_pos = witness_range(os + n, n);
    let q1_neg = witness_range(os + 2 * n, n);
    let c1 = witness_range(os + 3 * n, 2 * n - 2);
    let q2_pos = witness_range(os + 5 * n - 2, n);
    let q2_neg = witness_range(os + 6 * n - 2, n);
    let c2 = witness_range(os + 7 * n - 2, 2 * n - 2);

    // Eq1: px·px - x_sq = q1·p
    let prod_px_px = make_products(compiler, px.as_slice(), px.as_slice());

    let max_coeff_eq1: u64 = 1 + 1 + 2 * n as u64;
    emit_schoolbook_column_equations(
        compiler,
        &[(&prod_px_px, FieldElement::ONE)],
        &[(&x_sq, -FieldElement::ONE)],
        &q1_pos,
        Some(&q1_neg),
        &c1,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff_eq1,
    );

    // Eq2: py·py - x_sq·px - a·px - b = q2·p
    let prod_py_py = make_products(compiler, py.as_slice(), py.as_slice());
    let prod_xsq_px = make_products(compiler, &x_sq, px.as_slice());
    let b_limbs = allocate_pinned_constant_limbs(compiler, &params.curve_b_limbs[..n]);

    if a_is_zero {
        let max_coeff_eq2: u64 = 1 + 1 + 1 + 2 * n as u64;
        emit_schoolbook_column_equations(
            compiler,
            &[
                (&prod_py_py, FieldElement::ONE),
                (&prod_xsq_px, -FieldElement::ONE),
            ],
            &[(&b_limbs, -FieldElement::ONE)],
            &q2_pos,
            Some(&q2_neg),
            &c2,
            &params.p_limbs,
            n,
            params.limb_bits,
            max_coeff_eq2,
        );
    } else {
        let a_limbs = allocate_pinned_constant_limbs(compiler, &params.curve_a_limbs[..n]);
        let prod_a_px = make_products(compiler, &a_limbs, px.as_slice());

        let max_coeff_eq2: u64 = 1 + 1 + 1 + 1 + 2 * n as u64;
        emit_schoolbook_column_equations(
            compiler,
            &[
                (&prod_py_py, FieldElement::ONE),
                (&prod_xsq_px, -FieldElement::ONE),
                (&prod_a_px, -FieldElement::ONE),
            ],
            &[(&b_limbs, -FieldElement::ONE)],
            &q2_pos,
            Some(&q2_neg),
            &c2,
            &params.p_limbs,
            n,
            params.limb_bits,
            max_coeff_eq2,
        );
    }

    // Range checks on hint outputs
    let crb = carry_range_bits(params.limb_bits, max_coeff_sum, n);
    range_check_limbs_and_carries(
        range_checks,
        &[&x_sq, &q1_pos, &q1_neg, &q2_pos, &q2_neg],
        &[&c1, &c2],
        params.limb_bits,
        crb,
    );

    // Less-than-p check for x_sq
    less_than_p_check_vec(compiler, range_checks, &x_sq, params);
}

/// Hint-verified point doubling for non-native field (multi-limb).
pub fn point_double_verified_non_native(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    px: Limbs,
    py: Limbs,
    params: &MultiLimbParams,
) -> (Limbs, Limbs) {
    let n = params.num_limbs;
    assert!(n >= 2, "hint-verified non-native requires n >= 2");

    let max_coeff_sum: u64 = 2 + 3 + 1 + 2 * n as u64; // λy(2) + xx(3) + a(1) + pq_pos(N) + pq_neg(N)
    check_column_equation_fits(params.limb_bits, max_coeff_sum, n, "Merged EC double");

    // Allocate hint
    let os = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::NonNativeEcHint {
        output_start:    os,
        op:              NonNativeEcOp::Double,
        inputs:          vec![px.as_slice().to_vec(), py.as_slice().to_vec()],
        curve_a:         params.curve_a_raw,
        curve_b:         [0; 4], // unused for double
        field_modulus_p: params.modulus_raw,
        limb_bits:       params.limb_bits,
        num_limbs:       n as u32,
    });

    // Parse hint layout: [lambda(N), x3(N), y3(N),
    //   q1_pos(N), q1_neg(N), c1(2N-2),
    //   q2_pos(N), q2_neg(N), c2(2N-2),
    //   q3_pos(N), q3_neg(N), c3(2N-2)]
    // Total: 15N-6
    let lambda = witness_range(os, n);
    let x3 = witness_range(os + n, n);
    let y3 = witness_range(os + 2 * n, n);
    let q1_pos = witness_range(os + 3 * n, n);
    let q1_neg = witness_range(os + 4 * n, n);
    let c1 = witness_range(os + 5 * n, 2 * n - 2);
    let q2_pos = witness_range(os + 7 * n - 2, n);
    let q2_neg = witness_range(os + 8 * n - 2, n);
    let c2 = witness_range(os + 9 * n - 2, 2 * n - 2);
    let q3_pos = witness_range(os + 11 * n - 4, n);
    let q3_neg = witness_range(os + 12 * n - 4, n);
    let c3 = witness_range(os + 13 * n - 4, 2 * n - 2);

    let px_s = px.as_slice();
    let py_s = py.as_slice();

    // Eq1: 2*lambda*py - 3*px*px - a = q1*p
    let prod_lam_py = make_products(compiler, &lambda, py_s);
    let prod_px_px = make_products(compiler, px_s, px_s);
    let a_limbs = allocate_pinned_constant_limbs(compiler, &params.curve_a_limbs[..n]);

    let max_coeff_eq1: u64 = 2 + 3 + 1 + 2 * n as u64;
    emit_schoolbook_column_equations(
        compiler,
        &[
            (&prod_lam_py, FieldElement::from(2u64)),
            (&prod_px_px, -FieldElement::from(3u64)),
        ],
        &[(&a_limbs, -FieldElement::ONE)],
        &q1_pos,
        Some(&q1_neg),
        &c1,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff_eq1,
    );

    // Eq2: lambda² - x3 - 2*px = q2*p
    let prod_lam_lam = make_products(compiler, &lambda, &lambda);

    let max_coeff_eq2: u64 = 1 + 1 + 2 + 2 * n as u64;
    emit_schoolbook_column_equations(
        compiler,
        &[(&prod_lam_lam, FieldElement::ONE)],
        &[(&x3, -FieldElement::ONE), (px_s, -FieldElement::from(2u64))],
        &q2_pos,
        Some(&q2_neg),
        &c2,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff_eq2,
    );

    // Eq3: lambda*px - lambda*x3 - y3 - py = q3*p
    let prod_lam_px = make_products(compiler, &lambda, px_s);
    let prod_lam_x3 = make_products(compiler, &lambda, &x3);

    let max_coeff_eq3: u64 = 1 + 1 + 1 + 1 + 2 * n as u64;
    emit_schoolbook_column_equations(
        compiler,
        &[
            (&prod_lam_px, FieldElement::ONE),
            (&prod_lam_x3, -FieldElement::ONE),
        ],
        &[(&y3, -FieldElement::ONE), (py_s, -FieldElement::ONE)],
        &q3_pos,
        Some(&q3_neg),
        &c3,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff_eq3,
    );

    // Range checks on hint outputs
    // max_coeff across eqs: Eq1 = 6+2N, Eq2 = 4+2N, Eq3 = 4+2N → worst = 6+2N
    let max_coeff_carry = 6u64 + 2 * n as u64;
    let crb = carry_range_bits(params.limb_bits, max_coeff_carry, n);
    range_check_limbs_and_carries(
        range_checks,
        &[
            &lambda, &x3, &y3, &q1_pos, &q1_neg, &q2_pos, &q2_neg, &q3_pos, &q3_neg,
        ],
        &[&c1, &c2, &c3],
        params.limb_bits,
        crb,
    );

    // Less-than-p checks for lambda, x3, y3
    less_than_p_check_vec(compiler, range_checks, &lambda, params);
    less_than_p_check_vec(compiler, range_checks, &x3, params);
    less_than_p_check_vec(compiler, range_checks, &y3, params);

    (Limbs::from(x3.as_slice()), Limbs::from(y3.as_slice()))
}

/// Hint-verified point addition for non-native field (multi-limb).
pub fn point_add_verified_non_native(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x1: Limbs,
    y1: Limbs,
    x2: Limbs,
    y2: Limbs,
    params: &MultiLimbParams,
) -> (Limbs, Limbs) {
    let n = params.num_limbs;
    assert!(n >= 2, "hint-verified non-native requires n >= 2");

    let max_coeff: u64 = 1 + 1 + 1 + 1 + 2 * n as u64; // all 3 eqs: 1+1+1+1+2N
    check_column_equation_fits(params.limb_bits, max_coeff, n, "EC add");

    let os = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::NonNativeEcHint {
        output_start:    os,
        op:              NonNativeEcOp::Add,
        inputs:          vec![
            x1.as_slice().to_vec(),
            y1.as_slice().to_vec(),
            x2.as_slice().to_vec(),
            y2.as_slice().to_vec(),
        ],
        curve_a:         [0; 4], // unused for add
        curve_b:         [0; 4], // unused for add
        field_modulus_p: params.modulus_raw,
        limb_bits:       params.limb_bits,
        num_limbs:       n as u32,
    });

    // Parse hint layout: [lambda(N), x3(N), y3(N),
    //   q1_pos(N), q1_neg(N), c1(2N-2),
    //   q2_pos(N), q2_neg(N), c2(2N-2),
    //   q3_pos(N), q3_neg(N), c3(2N-2)]
    // Total: 15N-6
    let lambda = witness_range(os, n);
    let x3 = witness_range(os + n, n);
    let y3 = witness_range(os + 2 * n, n);
    let q1_pos = witness_range(os + 3 * n, n);
    let q1_neg = witness_range(os + 4 * n, n);
    let c1 = witness_range(os + 5 * n, 2 * n - 2);
    let q2_pos = witness_range(os + 7 * n - 2, n);
    let q2_neg = witness_range(os + 8 * n - 2, n);
    let c2 = witness_range(os + 9 * n - 2, 2 * n - 2);
    let q3_pos = witness_range(os + 11 * n - 4, n);
    let q3_neg = witness_range(os + 12 * n - 4, n);
    let c3 = witness_range(os + 13 * n - 4, 2 * n - 2);

    let x1_s = x1.as_slice();
    let y1_s = y1.as_slice();
    let x2_s = x2.as_slice();
    let y2_s = y2.as_slice();

    // Eq1: lambda*x2 - lambda*x1 - y2 + y1 = q1*p
    let prod_lam_x2 = make_products(compiler, &lambda, x2_s);
    let prod_lam_x1 = make_products(compiler, &lambda, x1_s);

    emit_schoolbook_column_equations(
        compiler,
        &[
            (&prod_lam_x2, FieldElement::ONE),
            (&prod_lam_x1, -FieldElement::ONE),
        ],
        &[(y2_s, -FieldElement::ONE), (y1_s, FieldElement::ONE)],
        &q1_pos,
        Some(&q1_neg),
        &c1,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff,
    );

    // Eq2: lambda² - x3 - x1 - x2 = q2*p
    let prod_lam_lam = make_products(compiler, &lambda, &lambda);

    emit_schoolbook_column_equations(
        compiler,
        &[(&prod_lam_lam, FieldElement::ONE)],
        &[
            (&x3, -FieldElement::ONE),
            (x1_s, -FieldElement::ONE),
            (x2_s, -FieldElement::ONE),
        ],
        &q2_pos,
        Some(&q2_neg),
        &c2,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff,
    );

    // Eq3: lambda*x1 - lambda*x3 - y3 - y1 = q3*p
    // Reuse prod_lam_x1 from Eq1
    let prod_lam_x3 = make_products(compiler, &lambda, &x3);

    emit_schoolbook_column_equations(
        compiler,
        &[
            (&prod_lam_x1, FieldElement::ONE),
            (&prod_lam_x3, -FieldElement::ONE),
        ],
        &[(&y3, -FieldElement::ONE), (y1_s, -FieldElement::ONE)],
        &q3_pos,
        Some(&q3_neg),
        &c3,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff,
    );

    // Range checks
    // max_coeff across all 3 eqs = 4+2N
    let max_coeff_carry = 4u64 + 2 * n as u64;
    let crb = carry_range_bits(params.limb_bits, max_coeff_carry, n);
    range_check_limbs_and_carries(
        range_checks,
        &[
            &lambda, &x3, &y3, &q1_pos, &q1_neg, &q2_pos, &q2_neg, &q3_pos, &q3_neg,
        ],
        &[&c1, &c2, &c3],
        params.limb_bits,
        crb,
    );

    // Less-than-p checks
    less_than_p_check_vec(compiler, range_checks, &lambda, params);
    less_than_p_check_vec(compiler, range_checks, &x3, params);
    less_than_p_check_vec(compiler, range_checks, &y3, params);

    (Limbs::from(x3.as_slice()), Limbs::from(y3.as_slice()))
}
