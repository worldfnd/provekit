//! Non-native hint-verified EC operations (multi-limb schoolbook).
//!
//! Each EC op allocates a prover hint and verifies it via schoolbook
//! column equations, avoiding step-by-step field inversions.

use {
    crate::{
        msm::{
            cost_model::{column_equation_max_bits, hint_carry_bits},
            multi_limb_arith::{
                emit_schoolbook_column_equations, less_than_p_check_multi, QuotientCarryWitnesses,
            },
            multi_limb_ops::EcFieldParams,
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

/// Soundness check: verify that merged column equations fit the native field.
fn check_column_equation_fits(limb_bits: u32, max_coeff_sum: u64, n: usize, op_name: &str) {
    let max_bits = column_equation_max_bits(limb_bits, max_coeff_sum, n);
    assert!(
        max_bits < FieldElement::MODULUS_BIT_SIZE,
        "{op_name} column equation overflow: limb_bits={limb_bits}, n={n}, needs {max_bits} bits",
    );
}

// ---------------------------------------------------------------------------
// Parsed hint layout for 3-equation EC ops (point double and add)
// ---------------------------------------------------------------------------

/// Parsed hint layout: [lambda(N), x3(N), y3(N),
///   q_pos\[0\](N), q_neg\[0\](N), carries\[0\](2N-2),
///   q_pos\[1\](N), q_neg\[1\](N), carries\[1\](2N-2),
///   q_pos\[2\](N), q_neg\[2\](N), carries\[2\](2N-2)]
/// Total: 15N-6 witnesses.
struct EcHint3Eq {
    lambda:  Vec<usize>,
    x3:      Vec<usize>,
    y3:      Vec<usize>,
    q_pos:   [Vec<usize>; 3],
    q_neg:   [Vec<usize>; 3],
    carries: [Vec<usize>; 3],
}

impl EcHint3Eq {
    fn parse(os: usize, n: usize) -> Self {
        Self {
            lambda:  witness_range(os, n),
            x3:      witness_range(os + n, n),
            y3:      witness_range(os + 2 * n, n),
            q_pos:   [
                witness_range(os + 3 * n, n),
                witness_range(os + 7 * n - 2, n),
                witness_range(os + 11 * n - 4, n),
            ],
            q_neg:   [
                witness_range(os + 4 * n, n),
                witness_range(os + 8 * n - 2, n),
                witness_range(os + 12 * n - 4, n),
            ],
            carries: [
                witness_range(os + 5 * n, 2 * n - 2),
                witness_range(os + 9 * n - 2, 2 * n - 2),
                witness_range(os + 13 * n - 4, 2 * n - 2),
            ],
        }
    }

    /// Range-check all hint outputs and verify lambda/x3/y3 < p.
    fn range_check_and_verify(
        &self,
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        max_coeff_sum: u64,
        params: &EcFieldParams,
    ) -> (Limbs, Limbs) {
        let n = params.num_limbs;
        let carry_range_bits = hint_carry_bits(params.limb_bits, max_coeff_sum, n);
        range_check_limbs_and_carries(
            range_checks,
            &[
                &self.lambda,
                &self.x3,
                &self.y3,
                &self.q_pos[0],
                &self.q_neg[0],
                &self.q_pos[1],
                &self.q_neg[1],
                &self.q_pos[2],
                &self.q_neg[2],
            ],
            &[&self.carries[0], &self.carries[1], &self.carries[2]],
            params.limb_bits,
            carry_range_bits,
        );
        for v in [&self.lambda, &self.x3, &self.y3] {
            less_than_p_check_multi(compiler, range_checks, Limbs::from(v.as_slice()), params);
        }
        (
            Limbs::from(self.x3.as_slice()),
            Limbs::from(self.y3.as_slice()),
        )
    }
}

/// Hint-verified on-curve check: y² = x³ + ax + b (mod p).
pub fn verify_on_curve_non_native(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    px: Limbs,
    py: Limbs,
    params: &EcFieldParams,
) {
    let n = params.num_limbs;
    assert!(n >= 2, "hint-verified on-curve check requires n >= 2");

    let a_is_zero = params.ec.curve_a_raw.iter().all(|&v| v == 0);

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
        inputs:          vec![px, py],
        curve_a:         params.ec.curve_a_raw,
        curve_b:         params.ec.curve_b_raw,
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
        &QuotientCarryWitnesses {
            q_pos:   &q1_pos,
            q_neg:   Some(&q1_neg),
            carries: &c1,
        },
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff_eq1,
    );

    // Eq2: py·py - x_sq·px - a·px - b = q2·p
    let prod_py_py = make_products(compiler, py.as_slice(), py.as_slice());
    let prod_xsq_px = make_products(compiler, &x_sq, px.as_slice());
    let b_wit = &params.ec.curve_b_witnesses;

    if a_is_zero {
        let max_coeff_eq2: u64 = 1 + 1 + 1 + 2 * n as u64;
        emit_schoolbook_column_equations(
            compiler,
            &[
                (&prod_py_py, FieldElement::ONE),
                (&prod_xsq_px, -FieldElement::ONE),
            ],
            &[(b_wit.as_slice(), -FieldElement::ONE)],
            &QuotientCarryWitnesses {
                q_pos:   &q2_pos,
                q_neg:   Some(&q2_neg),
                carries: &c2,
            },
            &params.p_limbs,
            n,
            params.limb_bits,
            max_coeff_eq2,
        );
    } else {
        let a_wit = &params.ec.curve_a_witnesses;
        let prod_a_px = make_products(compiler, a_wit, px.as_slice());

        let max_coeff_eq2: u64 = 1 + 1 + 1 + 1 + 2 * n as u64;
        emit_schoolbook_column_equations(
            compiler,
            &[
                (&prod_py_py, FieldElement::ONE),
                (&prod_xsq_px, -FieldElement::ONE),
                (&prod_a_px, -FieldElement::ONE),
            ],
            &[(b_wit.as_slice(), -FieldElement::ONE)],
            &QuotientCarryWitnesses {
                q_pos:   &q2_pos,
                q_neg:   Some(&q2_neg),
                carries: &c2,
            },
            &params.p_limbs,
            n,
            params.limb_bits,
            max_coeff_eq2,
        );
    }

    // Range checks on hint outputs
    let carry_range_bits = hint_carry_bits(params.limb_bits, max_coeff_sum, n);
    range_check_limbs_and_carries(
        range_checks,
        &[&x_sq, &q1_pos, &q1_neg, &q2_pos, &q2_neg],
        &[&c1, &c2],
        params.limb_bits,
        carry_range_bits,
    );

    // Less-than-p check for x_sq
    less_than_p_check_multi(compiler, range_checks, Limbs::from(x_sq.as_slice()), params);
}

/// Allocate a 3-equation EC hint, emit equations via closure, and range-check
/// outputs.
fn emit_3eq_ec_hint(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    op: NonNativeEcOp,
    inputs: Vec<Limbs>,
    curve_a: [u64; 4],
    curve_b: [u64; 4],
    max_coeff_sum: u64,
    op_name: &str,
    params: &EcFieldParams,
    build_equations: impl FnOnce(&mut NoirToR1CSCompiler, &EcHint3Eq, &EcFieldParams),
) -> (Limbs, Limbs) {
    let n = params.num_limbs;
    assert!(n >= 2, "hint-verified non-native requires n >= 2");
    check_column_equation_fits(params.limb_bits, max_coeff_sum, n, op_name);

    let os = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::NonNativeEcHint {
        output_start: os,
        op,
        inputs,
        curve_a,
        curve_b,
        field_modulus_p: params.modulus_raw,
        limb_bits: params.limb_bits,
        num_limbs: n as u32,
    });

    let h = EcHint3Eq::parse(os, n);
    build_equations(compiler, &h, params);
    h.range_check_and_verify(compiler, range_checks, max_coeff_sum, params)
}

/// Hint-verified point doubling for non-native field (multi-limb).
pub fn point_double_verified_non_native(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    px: Limbs,
    py: Limbs,
    params: &EcFieldParams,
) -> (Limbs, Limbs) {
    let n = params.num_limbs;
    emit_3eq_ec_hint(
        compiler,
        range_checks,
        NonNativeEcOp::Double,
        vec![px, py],
        params.ec.curve_a_raw,
        [0; 4],
        6 + 2 * n as u64,
        "Merged EC double",
        params,
        |compiler, h, params| {
            let px_s = px.as_slice();
            let py_s = py.as_slice();

            // Eq1: 2*lambda*py - 3*px*px - a = q1*p
            let prod_lam_py = make_products(compiler, &h.lambda, py_s);
            let prod_px_px = make_products(compiler, px_s, px_s);
            let a_wit = &params.ec.curve_a_witnesses;

            emit_schoolbook_column_equations(
                compiler,
                &[
                    (&prod_lam_py, FieldElement::from(2u64)),
                    (&prod_px_px, -FieldElement::from(3u64)),
                ],
                &[(a_wit.as_slice(), -FieldElement::ONE)],
                &QuotientCarryWitnesses {
                    q_pos:   &h.q_pos[0],
                    q_neg:   Some(&h.q_neg[0]),
                    carries: &h.carries[0],
                },
                &params.p_limbs,
                n,
                params.limb_bits,
                2 + 3 + 1 + 2 * n as u64,
            );

            // Eq2: lambda² - x3 - 2*px = q2*p
            let prod_lam_lam = make_products(compiler, &h.lambda, &h.lambda);

            emit_schoolbook_column_equations(
                compiler,
                &[(&prod_lam_lam, FieldElement::ONE)],
                &[
                    (&h.x3, -FieldElement::ONE),
                    (px_s, -FieldElement::from(2u64)),
                ],
                &QuotientCarryWitnesses {
                    q_pos:   &h.q_pos[1],
                    q_neg:   Some(&h.q_neg[1]),
                    carries: &h.carries[1],
                },
                &params.p_limbs,
                n,
                params.limb_bits,
                1 + 1 + 2 + 2 * n as u64,
            );

            // Eq3: lambda*px - lambda*x3 - y3 - py = q3*p
            let prod_lam_px = make_products(compiler, &h.lambda, px_s);
            let prod_lam_x3 = make_products(compiler, &h.lambda, &h.x3);

            emit_schoolbook_column_equations(
                compiler,
                &[
                    (&prod_lam_px, FieldElement::ONE),
                    (&prod_lam_x3, -FieldElement::ONE),
                ],
                &[(&h.y3, -FieldElement::ONE), (py_s, -FieldElement::ONE)],
                &QuotientCarryWitnesses {
                    q_pos:   &h.q_pos[2],
                    q_neg:   Some(&h.q_neg[2]),
                    carries: &h.carries[2],
                },
                &params.p_limbs,
                n,
                params.limb_bits,
                1 + 1 + 1 + 1 + 2 * n as u64,
            );
        },
    )
}

/// Hint-verified point addition for non-native field (multi-limb).
pub fn point_add_verified_non_native(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x1: Limbs,
    y1: Limbs,
    x2: Limbs,
    y2: Limbs,
    params: &EcFieldParams,
) -> (Limbs, Limbs) {
    let n = params.num_limbs;
    let max_coeff: u64 = 4 + 2 * n as u64;
    emit_3eq_ec_hint(
        compiler,
        range_checks,
        NonNativeEcOp::Add,
        vec![x1, y1, x2, y2],
        [0; 4],
        [0; 4],
        max_coeff,
        "EC add",
        params,
        |compiler, h, params| {
            let x1_s = x1.as_slice();
            let y1_s = y1.as_slice();
            let x2_s = x2.as_slice();
            let y2_s = y2.as_slice();

            // Eq1: lambda*x2 - lambda*x1 - y2 + y1 = q1*p
            let prod_lam_x2 = make_products(compiler, &h.lambda, x2_s);
            let prod_lam_x1 = make_products(compiler, &h.lambda, x1_s);

            emit_schoolbook_column_equations(
                compiler,
                &[
                    (&prod_lam_x2, FieldElement::ONE),
                    (&prod_lam_x1, -FieldElement::ONE),
                ],
                &[(y2_s, -FieldElement::ONE), (y1_s, FieldElement::ONE)],
                &QuotientCarryWitnesses {
                    q_pos:   &h.q_pos[0],
                    q_neg:   Some(&h.q_neg[0]),
                    carries: &h.carries[0],
                },
                &params.p_limbs,
                n,
                params.limb_bits,
                max_coeff,
            );

            // Eq2: lambda² - x3 - x1 - x2 = q2*p
            let prod_lam_lam = make_products(compiler, &h.lambda, &h.lambda);

            emit_schoolbook_column_equations(
                compiler,
                &[(&prod_lam_lam, FieldElement::ONE)],
                &[
                    (&h.x3, -FieldElement::ONE),
                    (x1_s, -FieldElement::ONE),
                    (x2_s, -FieldElement::ONE),
                ],
                &QuotientCarryWitnesses {
                    q_pos:   &h.q_pos[1],
                    q_neg:   Some(&h.q_neg[1]),
                    carries: &h.carries[1],
                },
                &params.p_limbs,
                n,
                params.limb_bits,
                max_coeff,
            );

            // Eq3: lambda*x1 - lambda*x3 - y3 - y1 = q3*p
            // Reuse prod_lam_x1 from Eq1
            let prod_lam_x3 = make_products(compiler, &h.lambda, &h.x3);

            emit_schoolbook_column_equations(
                compiler,
                &[
                    (&prod_lam_x1, FieldElement::ONE),
                    (&prod_lam_x3, -FieldElement::ONE),
                ],
                &[(&h.y3, -FieldElement::ONE), (y1_s, -FieldElement::ONE)],
                &QuotientCarryWitnesses {
                    q_pos:   &h.q_pos[2],
                    q_neg:   Some(&h.q_neg[2]),
                    carries: &h.carries[2],
                },
                &params.p_limbs,
                n,
                params.limb_bits,
                max_coeff,
            );
        },
    )
}
