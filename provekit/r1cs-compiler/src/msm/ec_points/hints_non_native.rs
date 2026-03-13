//! Non-native hint-verified EC operations (multi-limb schoolbook).
//!
//! These replace the step-by-step MultiLimbOps chain with prover hints verified
//! via schoolbook column equations. Each bilinear mod-p equation is checked by:
//! 1. Pre-computing product witnesses a\[i\]*b\[j\]
//! 2. Column equations: Σ coeff·prod\[k\] + linear\[k\] + carry_in + offset = Σ
//!    p\[i\]*q\[j\] + carry_out * W
//! Since p is constant, p\[i\]*q\[j\] terms are linear in q (no product
//! witness).

use {
    crate::{
        msm::{multi_limb_arith::less_than_p_check_multi, multi_limb_ops::MultiLimbParams, Limbs},
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
    limb_values
        .iter()
        .map(|&val| {
            let w = compiler.num_witnesses();
            compiler.add_witness_builder(WitnessBuilder::Constant(
                provekit_common::witness::ConstantTerm(w, val),
            ));
            compiler.r1cs.add_constraint(
                &[(FieldElement::ONE, compiler.witness_one())],
                &[(FieldElement::ONE, w)],
                &[(val, compiler.witness_one())],
            );
            w
        })
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
    let n = v.len();
    let mut limbs = Limbs::new(n);
    for i in 0..n {
        limbs[i] = v[i];
    }
    less_than_p_check_multi(
        compiler,
        range_checks,
        limbs,
        &params.p_minus_1_limbs,
        params.two_pow_w,
        params.limb_bits,
    );
}

/// Compute carry range bits for hint-verified column equations.
fn carry_range_bits(limb_bits: u32, max_coeff_sum: u64, n: usize) -> u32 {
    let extra_bits = ((max_coeff_sum as f64 * n as f64).log2().ceil() as u32) + 1;
    limb_bits + extra_bits
}

/// Soundness check: verify that merged column equations fit the native field.
fn check_column_equation_fits(limb_bits: u32, max_coeff_sum: u64, n: usize, op_name: &str) {
    let extra_bits = ((max_coeff_sum as f64 * n as f64).log2().ceil() as u32) + 1;
    let max_bits = 2 * limb_bits + extra_bits + 1;
    assert!(
        max_bits < FieldElement::MODULUS_BIT_SIZE,
        "{op_name} column equation overflow: limb_bits={limb_bits}, n={n}, needs {max_bits} bits",
    );
}

/// Emit schoolbook column equations for a merged verification equation.
///
/// Verifies: Σ (coeff_i × A_i ⊗ B_i) + Σ linear_k = q·p  (mod p, as integers)
///
/// `product_sets`: each (products_2d, coefficient) where products_2d\[i\]\[j\]
///   is the witness index for a\[i\]*b\[j\].
/// `linear_limbs`: each (limb_witnesses, coefficient) for non-product terms
///   (limb_witnesses has N entries, zero-padded).
/// `q_witnesses`: quotient limbs (N entries).
/// `carry_witnesses`: unsigned-offset carry witnesses (2N-2 entries).
fn emit_schoolbook_column_equations(
    compiler: &mut NoirToR1CSCompiler,
    product_sets: &[(&[Vec<usize>], FieldElement)], // (products[i][j], coeff)
    linear_limbs: &[(&[usize], FieldElement)],      // (limb_witnesses, coeff)
    q_witnesses: &[usize],
    carry_witnesses: &[usize],
    p_limbs: &[FieldElement],
    n: usize,
    limb_bits: u32,
    max_coeff_sum: u64,
) {
    let w1 = compiler.witness_one();
    let two_pow_w = FieldElement::from(2u64).pow([limb_bits as u64]);

    // Carry offset scaled for the merged equation's larger coefficients
    let extra_bits = ((max_coeff_sum as f64 * n as f64).log2().ceil() as u32) + 1;
    let carry_offset_bits = limb_bits + extra_bits;
    let carry_offset_fe = FieldElement::from(2u64).pow([carry_offset_bits as u64]);
    let offset_w = FieldElement::from(2u64).pow([(carry_offset_bits + limb_bits) as u64]);
    let offset_w_minus_carry = offset_w - carry_offset_fe;

    let num_columns = 2 * n - 1;

    for k in 0..num_columns {
        // LHS: Σ coeff * products[i][j] for i+j=k + carry_in + offset
        let mut lhs_terms: Vec<(FieldElement, usize)> = Vec::new();

        for &(products, coeff) in product_sets {
            for i in 0..n {
                let j_val = k as isize - i as isize;
                if j_val >= 0 && (j_val as usize) < n {
                    lhs_terms.push((coeff, products[i][j_val as usize]));
                }
            }
        }

        // Add linear terms (for k < N only, since linear_limbs are N-length)
        for &(limbs, coeff) in linear_limbs {
            if k < limbs.len() {
                lhs_terms.push((coeff, limbs[k]));
            }
        }

        // Add carry_in and offset
        if k > 0 {
            lhs_terms.push((FieldElement::ONE, carry_witnesses[k - 1]));
            lhs_terms.push((offset_w_minus_carry, w1));
        } else {
            lhs_terms.push((offset_w, w1));
        }

        // RHS: Σ p[i]*q[j] for i+j=k + carry_out * W (or offset at last column)
        let mut rhs_terms: Vec<(FieldElement, usize)> = Vec::new();
        for i in 0..n {
            let j_val = k as isize - i as isize;
            if j_val >= 0 && (j_val as usize) < n {
                rhs_terms.push((p_limbs[i], q_witnesses[j_val as usize]));
            }
        }

        if k < num_columns - 1 {
            rhs_terms.push((two_pow_w, carry_witnesses[k]));
        } else {
            // Last column: balance with offset_w (no outgoing carry)
            rhs_terms.push((offset_w, w1));
        }

        compiler
            .r1cs
            .add_constraint(&lhs_terms, &[(FieldElement::ONE, w1)], &rhs_terms);
    }
}

/// Helper to convert witness Vec to Limbs.
fn vec_to_limbs(v: &[usize]) -> Limbs {
    let n = v.len();
    let mut limbs = Limbs::new(n);
    for i in 0..n {
        limbs[i] = v[i];
    }
    limbs
}

/// Hint-verified on-curve check for non-native field (multi-limb).
///
/// Verifies y² = x³ + ax + b (mod p) via two schoolbook column equations:
///   Eq1: x·x - x_sq = q1·p              (x_sq correctness)
///   Eq2: y·y - x_sq·x - a·x - b = q2·p  (on-curve)
///
/// Total: (7N-4)W hint + 3N² products (or 2N² when a=0) + 2×(2N-1) column
///        constraints + 1 less-than-p check.
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
        4 + n as u64
    } else {
        5 + n as u64
    };
    check_column_equation_fits(params.limb_bits, max_coeff_sum, n, "On-curve");

    // Allocate hint
    let os = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::NonNativeEcHint {
        output_start:    os,
        op:              NonNativeEcOp::OnCurve,
        inputs:          vec![px.as_slice()[..n].to_vec(), py.as_slice()[..n].to_vec()],
        curve_a:         params.curve_a_raw,
        curve_b:         params.curve_b_raw,
        field_modulus_p: params.modulus_raw,
        limb_bits:       params.limb_bits,
        num_limbs:       n as u32,
    });

    // Parse hint layout: [x_sq(N), q1(N), c1(2N-2), q2(N), c2(2N-2)]
    let x_sq = witness_range(os, n);
    let q1 = witness_range(os + n, n);
    let c1 = witness_range(os + 2 * n, 2 * n - 2);
    let q2 = witness_range(os + 4 * n - 2, n);
    let c2 = witness_range(os + 5 * n - 2, 2 * n - 2);

    // Eq1: px·px - x_sq = q1·p
    let prod_px_px = make_products(compiler, &px.as_slice()[..n], &px.as_slice()[..n]);

    let max_coeff_eq1: u64 = 1 + 1 + n as u64;
    emit_schoolbook_column_equations(
        compiler,
        &[(&prod_px_px, FieldElement::ONE)],
        &[(&x_sq, -FieldElement::ONE)],
        &q1,
        &c1,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff_eq1,
    );

    // Eq2: py·py - x_sq·px - a·px - b = q2·p
    let prod_py_py = make_products(compiler, &py.as_slice()[..n], &py.as_slice()[..n]);
    let prod_xsq_px = make_products(compiler, &x_sq, &px.as_slice()[..n]);
    let b_limbs = allocate_pinned_constant_limbs(compiler, &params.curve_b_limbs[..n]);

    if a_is_zero {
        let max_coeff_eq2: u64 = 1 + 1 + 1 + n as u64;
        emit_schoolbook_column_equations(
            compiler,
            &[
                (&prod_py_py, FieldElement::ONE),
                (&prod_xsq_px, -FieldElement::ONE),
            ],
            &[(&b_limbs, -FieldElement::ONE)],
            &q2,
            &c2,
            &params.p_limbs,
            n,
            params.limb_bits,
            max_coeff_eq2,
        );
    } else {
        let a_limbs = allocate_pinned_constant_limbs(compiler, &params.curve_a_limbs[..n]);
        let prod_a_px = make_products(compiler, &a_limbs, &px.as_slice()[..n]);

        let max_coeff_eq2: u64 = 1 + 1 + 1 + 1 + n as u64;
        emit_schoolbook_column_equations(
            compiler,
            &[
                (&prod_py_py, FieldElement::ONE),
                (&prod_xsq_px, -FieldElement::ONE),
                (&prod_a_px, -FieldElement::ONE),
            ],
            &[(&b_limbs, -FieldElement::ONE)],
            &q2,
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
        &[&x_sq, &q1, &q2],
        &[&c1, &c2],
        params.limb_bits,
        crb,
    );

    // Less-than-p check for x_sq
    less_than_p_check_vec(compiler, range_checks, &x_sq, params);
}

/// Hint-verified point doubling for non-native field (multi-limb).
///
/// Allocates NonNativeEcDoubleHint → (lambda, x3, y3, q1, c1, q2, c2, q3, c3).
/// Verifies via schoolbook column equations on 3 EC equations:
///   Eq1: 2·lambda·py - 3·px² - a = q1·p    (2N² products: lam·py, px·px)
///   Eq2: lambda² - x3 - 2·px = q2·p        (1N² products: lam·lam)
///   Eq3: lambda·(px - x3) - y3 - py = q3·p (2N² products: lam·px, lam·x3)
///
/// Total: (12N-6)W hint + 5N²+N products + 3×(2N-1) column constraints
///        + 3 less-than-p checks.
pub fn point_double_verified_non_native(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    px: Limbs,
    py: Limbs,
    params: &MultiLimbParams,
) -> (Limbs, Limbs) {
    let n = params.num_limbs;
    assert!(n >= 2, "hint-verified non-native requires n >= 2");

    let max_coeff_sum: u64 = 2 + 3 + 1 + n as u64; // λy(2) + xx(3) + a(1) + pq(N)
    check_column_equation_fits(params.limb_bits, max_coeff_sum, n, "Merged EC double");

    // Allocate hint
    let os = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::NonNativeEcHint {
        output_start:    os,
        op:              NonNativeEcOp::Double,
        inputs:          vec![px.as_slice()[..n].to_vec(), py.as_slice()[..n].to_vec()],
        curve_a:         params.curve_a_raw,
        curve_b:         [0; 4], // unused for double
        field_modulus_p: params.modulus_raw,
        limb_bits:       params.limb_bits,
        num_limbs:       n as u32,
    });

    // Parse hint layout: [lambda(N), x3(N), y3(N), q1(N), c1(2N-2), q2(N),
    // c2(2N-2), q3(N), c3(2N-2)]
    let lambda = witness_range(os, n);
    let x3 = witness_range(os + n, n);
    let y3 = witness_range(os + 2 * n, n);
    let q1 = witness_range(os + 3 * n, n);
    let c1 = witness_range(os + 4 * n, 2 * n - 2);
    let q2 = witness_range(os + 6 * n - 2, n);
    let c2 = witness_range(os + 7 * n - 2, 2 * n - 2);
    let q3 = witness_range(os + 9 * n - 4, n);
    let c3 = witness_range(os + 10 * n - 4, 2 * n - 2);

    let px_s = &px.as_slice()[..n];
    let py_s = &py.as_slice()[..n];

    // Eq1: 2*lambda*py - 3*px*px - a = q1*p
    let prod_lam_py = make_products(compiler, &lambda, py_s);
    let prod_px_px = make_products(compiler, px_s, px_s);
    let a_limbs = allocate_pinned_constant_limbs(compiler, &params.curve_a_limbs[..n]);

    let max_coeff_eq1: u64 = 2 + 3 + 1 + n as u64;
    emit_schoolbook_column_equations(
        compiler,
        &[
            (&prod_lam_py, FieldElement::from(2u64)),
            (&prod_px_px, -FieldElement::from(3u64)),
        ],
        &[(&a_limbs, -FieldElement::ONE)],
        &q1,
        &c1,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff_eq1,
    );

    // Eq2: lambda² - x3 - 2*px = q2*p
    let prod_lam_lam = make_products(compiler, &lambda, &lambda);

    let max_coeff_eq2: u64 = 1 + 1 + 2 + n as u64;
    emit_schoolbook_column_equations(
        compiler,
        &[(&prod_lam_lam, FieldElement::ONE)],
        &[(&x3, -FieldElement::ONE), (px_s, -FieldElement::from(2u64))],
        &q2,
        &c2,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff_eq2,
    );

    // Eq3: lambda*px - lambda*x3 - y3 - py = q3*p
    let prod_lam_px = make_products(compiler, &lambda, px_s);
    let prod_lam_x3 = make_products(compiler, &lambda, &x3);

    let max_coeff_eq3: u64 = 1 + 1 + 1 + 1 + n as u64;
    emit_schoolbook_column_equations(
        compiler,
        &[
            (&prod_lam_px, FieldElement::ONE),
            (&prod_lam_x3, -FieldElement::ONE),
        ],
        &[(&y3, -FieldElement::ONE), (py_s, -FieldElement::ONE)],
        &q3,
        &c3,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff_eq3,
    );

    // Range checks on hint outputs
    // max_coeff across eqs: Eq1 = 6+N, Eq2 = 4+N, Eq3 = 4+N → worst = 6+N
    let max_coeff_carry = 6u64 + n as u64;
    let crb = carry_range_bits(params.limb_bits, max_coeff_carry, n);
    range_check_limbs_and_carries(
        range_checks,
        &[&lambda, &x3, &y3, &q1, &q2, &q3],
        &[&c1, &c2, &c3],
        params.limb_bits,
        crb,
    );

    // Less-than-p checks for lambda, x3, y3
    less_than_p_check_vec(compiler, range_checks, &lambda, params);
    less_than_p_check_vec(compiler, range_checks, &x3, params);
    less_than_p_check_vec(compiler, range_checks, &y3, params);

    (vec_to_limbs(&x3), vec_to_limbs(&y3))
}

/// Hint-verified point addition for non-native field (multi-limb).
///
/// Same approach as `point_double_verified_non_native` but verifies:
///   Eq1: lambda·(x2-x1) - (y2-y1) = q1·p  (2N² products: lam·x2, lam·x1)
///   Eq2: lambda² - x3 - x1 - x2 = q2·p    (1N² products: lam·lam)
///   Eq3: lambda·(x1-x3) - y3 - y1 = q3·p  (1N² products: lam·x3; lam·x1
/// reused)
///
/// Total: (12N-6)W hint + 4N² products + 3×(2N-1) column constraints
///        + 3 less-than-p checks.
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

    let max_coeff: u64 = 1 + 1 + 1 + 1 + n as u64; // all 3 eqs: 1+1+1+1+N
    check_column_equation_fits(params.limb_bits, max_coeff, n, "EC add");

    let os = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::NonNativeEcHint {
        output_start:    os,
        op:              NonNativeEcOp::Add,
        inputs:          vec![
            x1.as_slice()[..n].to_vec(),
            y1.as_slice()[..n].to_vec(),
            x2.as_slice()[..n].to_vec(),
            y2.as_slice()[..n].to_vec(),
        ],
        curve_a:         [0; 4], // unused for add
        curve_b:         [0; 4], // unused for add
        field_modulus_p: params.modulus_raw,
        limb_bits:       params.limb_bits,
        num_limbs:       n as u32,
    });

    let lambda = witness_range(os, n);
    let x3 = witness_range(os + n, n);
    let y3 = witness_range(os + 2 * n, n);
    let q1 = witness_range(os + 3 * n, n);
    let c1 = witness_range(os + 4 * n, 2 * n - 2);
    let q2 = witness_range(os + 6 * n - 2, n);
    let c2 = witness_range(os + 7 * n - 2, 2 * n - 2);
    let q3 = witness_range(os + 9 * n - 4, n);
    let c3 = witness_range(os + 10 * n - 4, 2 * n - 2);

    let x1_s = &x1.as_slice()[..n];
    let y1_s = &y1.as_slice()[..n];
    let x2_s = &x2.as_slice()[..n];
    let y2_s = &y2.as_slice()[..n];

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
        &q1,
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
        &q2,
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
        &q3,
        &c3,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff,
    );

    // Range checks
    // max_coeff across all 3 eqs = 4+N
    let max_coeff_carry = 4u64 + n as u64;
    let crb = carry_range_bits(params.limb_bits, max_coeff_carry, n);
    range_check_limbs_and_carries(
        range_checks,
        &[&lambda, &x3, &y3, &q1, &q2, &q3],
        &[&c1, &c2, &c3],
        params.limb_bits,
        crb,
    );

    // Less-than-p checks
    less_than_p_check_vec(compiler, range_checks, &lambda, params);
    less_than_p_check_vec(compiler, range_checks, &x3, params);
    less_than_p_check_vec(compiler, range_checks, &y3, params);

    (vec_to_limbs(&x3), vec_to_limbs(&y3))
}
