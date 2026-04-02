//! N-limb modular arithmetic for EC field operations.
//!
//! Provides add/sub/mul/negate mod p for both single-limb (N=1) and multi-limb
//! (N≥2) representations, plus `compute_is_zero` and `less_than_p` checks.

use {
    super::{ceil_log2, multi_limb_ops::ModulusParams, Limbs},
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    ark_ff::{AdditiveGroup, Field, PrimeField},
    provekit_common::{
        witness::{SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::collections::BTreeMap,
};

/// Distinguishes modular addition from subtraction in the shared core.
enum ModularOp {
    Add,
    Sub,
}

/// Checks if value is zero or not (used by all N values).
/// Returns a boolean witness: 1 if zero, 0 if non-zero.
///
/// Uses SafeInverse (not Inverse) because the input value may be zero.
/// SafeInverse outputs 0 when the input is 0, and is solved in the Other
/// layer (not batch-inverted), so zero inputs don't poison the batch.
#[must_use]
pub fn compute_is_zero(compiler: &mut NoirToR1CSCompiler, value: usize) -> usize {
    let value_inv = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::SafeInverse(value_inv, value));

    let value_mul_value_inv = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::Product(
        value_mul_value_inv,
        value,
        value_inv,
    ));

    let is_zero = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::Sum(is_zero, vec![
        SumTerm(Some(FieldElement::ONE), compiler.witness_one()),
        SumTerm(Some(-FieldElement::ONE), value_mul_value_inv),
    ]));

    // v × v^(-1) = 1 - is_zero
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, value)],
        &[(FieldElement::ONE, value_inv)],
        &[
            (FieldElement::ONE, compiler.witness_one()),
            (-FieldElement::ONE, is_zero),
        ],
    );
    // v × is_zero = 0
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, value)],
        &[(FieldElement::ONE, is_zero)],
        &[(FieldElement::ZERO, compiler.witness_one())],
    );

    is_zero
}

// ---------------------------------------------------------------------------
// N≥2 multi-limb path (generalization of wide_ops.rs)
// ---------------------------------------------------------------------------

/// Shared core for `add_mod_p_multi` and `sub_mod_p_multi`.
fn add_sub_mod_p_core(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    op: ModularOp,
    a: Limbs,
    b: Limbs,
    params: &ModulusParams,
) -> Limbs {
    let n = a.len();
    assert!(n >= 2, "add/sub_mod_p_multi requires n >= 2, got n={n}");
    let w1 = compiler.witness_one();

    // Witness: q ∈ {0, 1}
    let q = compiler.num_witnesses();
    match op {
        ModularOp::Add => {
            compiler.add_witness_builder(WitnessBuilder::MultiLimbAddQuotient {
                output:    q,
                a_limbs:   a.as_slice().to_vec(),
                b_limbs:   b.as_slice().to_vec(),
                modulus:   params.modulus_raw,
                limb_bits: params.limb_bits,
                num_limbs: n as u32,
            });
        }
        ModularOp::Sub => {
            compiler.add_witness_builder(WitnessBuilder::MultiLimbSubBorrow {
                output:    q,
                a_limbs:   a.as_slice().to_vec(),
                b_limbs:   b.as_slice().to_vec(),
                modulus:   params.modulus_raw,
                limb_bits: params.limb_bits,
                num_limbs: n as u32,
            });
        }
    }
    // q is boolean
    compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, q)], &[(FieldElement::ONE, q)], &[(
            FieldElement::ONE,
            q,
        )]);

    let mut r = Limbs::new();
    let mut carry_prev: Option<usize> = None;

    for i in 0..n {
        // Combine w1 terms to avoid duplicate column indices.
        // The offset 2^W is folded into w1_coeff (with -1 for carry_prev
        // which also uses w1 implicitly via SumTerm(None, ...)).
        let w1_coeff = if carry_prev.is_some() {
            params.two_pow_w - FieldElement::ONE
        } else {
            params.two_pow_w
        };
        let mut terms = vec![SumTerm(None, a[i])];
        match op {
            ModularOp::Add => {
                terms.push(SumTerm(None, b[i]));
                terms.push(SumTerm(Some(w1_coeff), w1));
                terms.push(SumTerm(Some(-params.p_limbs[i]), q));
            }
            ModularOp::Sub => {
                terms.push(SumTerm(Some(-FieldElement::ONE), b[i]));
                terms.push(SumTerm(Some(params.p_limbs[i]), q));
                terms.push(SumTerm(Some(w1_coeff), w1));
            }
        }
        if let Some(carry) = carry_prev {
            terms.push(SumTerm(None, carry));
        }

        // carry = floor(sum(terms) / 2^W)
        let carry = compiler.num_witnesses();
        compiler.add_witness_builder(WitnessBuilder::SumQuotient {
            output:  carry,
            terms:   terms.clone(),
            divisor: params.two_pow_w,
        });

        // Merged constraint: r[i] = sum(terms) - carry * 2^W
        terms.push(SumTerm(Some(-params.two_pow_w), carry));
        r.push(compiler.add_sum(terms));
        carry_prev = Some(carry);
    }

    less_than_p_check_multi(compiler, range_checks, r, params);

    r
}

/// (a + b) mod p for multi-limb values.
#[must_use]
pub fn add_mod_p_multi(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    a: Limbs,
    b: Limbs,
    params: &ModulusParams,
) -> Limbs {
    add_sub_mod_p_core(compiler, range_checks, ModularOp::Add, a, b, params)
}

/// Negate a multi-limb value: computes `p - y` directly via borrow chain.
#[must_use]
pub fn negate_mod_p_multi(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    y: Limbs,
    params: &ModulusParams,
) -> Limbs {
    let n = y.len();
    assert!(n >= 2, "negate_mod_p_multi requires n >= 2, got n={n}");
    let w1 = compiler.witness_one();

    let mut r = Limbs::new();
    let mut borrow_prev: Option<usize> = None;

    for i in 0..n {
        // Combine w1 terms to avoid duplicate column indices.
        let w1_coeff = if borrow_prev.is_some() {
            params.p_limbs[i] + params.two_pow_w - FieldElement::ONE
        } else {
            params.p_limbs[i] + params.two_pow_w
        };
        let mut terms = vec![
            SumTerm(Some(w1_coeff), w1),
            SumTerm(Some(-FieldElement::ONE), y[i]),
        ];
        if let Some(borrow) = borrow_prev {
            terms.push(SumTerm(None, borrow));
        }

        // borrow = floor(sum(terms) / 2^W)
        let borrow = compiler.num_witnesses();
        compiler.add_witness_builder(WitnessBuilder::SumQuotient {
            output:  borrow,
            terms:   terms.clone(),
            divisor: params.two_pow_w,
        });

        // Merged constraint: r[i] = sum(terms) - borrow * 2^W
        terms.push(SumTerm(Some(-params.two_pow_w), borrow));
        let ri = compiler.add_sum(terms);
        r.push(ri);

        // Range check r[i] — ensures borrow is uniquely determined
        range_checks.entry(params.limb_bits).or_default().push(ri);

        borrow_prev = Some(borrow);
    }

    r
}

/// (a - b) mod p for multi-limb values.
#[must_use]
pub fn sub_mod_p_multi(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    a: Limbs,
    b: Limbs,
    params: &ModulusParams,
) -> Limbs {
    add_sub_mod_p_core(compiler, range_checks, ModularOp::Sub, a, b, params)
}

/// (a * b) mod p for multi-limb values using schoolbook multiplication.
#[must_use]
pub fn mul_mod_p_multi(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    a: Limbs,
    b: Limbs,
    params: &ModulusParams,
) -> Limbs {
    let n = a.len();
    let limb_bits = params.limb_bits;
    assert!(n >= 2, "mul_mod_p_multi requires n >= 2, got n={n}");

    // Soundness: column values must fit the native field.
    {
        let ceil_log2_n = ceil_log2(n as u64);
        let max_bits = 2 * limb_bits + ceil_log2_n + 3;
        assert!(
            max_bits < FieldElement::MODULUS_BIT_SIZE,
            "Schoolbook column equation overflow: limb_bits={limb_bits}, n={n} limbs requires \
             {max_bits} bits, but native field is only {} bits. Use smaller limb_bits.",
            FieldElement::MODULUS_BIT_SIZE,
        );
    }

    let num_carries = 2 * n - 2;
    // Carry offset uses max_coeff_sum=1 (products only). The soundness check
    // above already verified the full column value fits the native field.
    let max_coeff_sum: u64 = 1;
    let extra_bits = ceil_log2(max_coeff_sum * n as u64) + 1;
    let carry_offset_bits = limb_bits + extra_bits;

    // Step 1: Allocate hint witnesses (q limbs, r limbs, carries)
    let os = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::MultiLimbMulModHint {
        output_start: os,
        a_limbs: a.as_slice().to_vec(),
        b_limbs: b.as_slice().to_vec(),
        modulus: params.modulus_raw,
        limb_bits,
        num_limbs: n as u32,
    });

    // q[0..n), r[n..2n), carries[2n..4n-2)
    let q: Vec<usize> = (0..n).map(|i| os + i).collect();
    let r_indices: Vec<usize> = (0..n).map(|i| os + n + i).collect();
    let cu: Vec<usize> = (0..num_carries).map(|i| os + 2 * n + i).collect();

    // Step 2: Product witnesses for a[i]*b[j] (n² R1CS constraints)
    let mut ab_products = vec![vec![0usize; n]; n];
    for i in 0..n {
        for j in 0..n {
            ab_products[i][j] = compiler.add_product(a[i], b[j]);
        }
    }

    // Step 3: Column equations (2n-1 R1CS constraints)
    // Equation: a·b - r = p·q (r on LHS with negative coeff, unsigned quotient)
    emit_schoolbook_column_equations(
        compiler,
        &[(&ab_products, FieldElement::ONE)],
        &[(&r_indices, -FieldElement::ONE)],
        &QuotientCarryWitnesses {
            q_pos:   &q,
            q_neg:   None,
            carries: &cu,
        },
        &params.p_limbs,
        n,
        limb_bits,
        max_coeff_sum,
    );

    // Step 4: less-than-p check and range checks on r
    let mut r_limbs = Limbs::new();
    for &ri in &r_indices {
        r_limbs.push(ri);
    }
    less_than_p_check_multi(compiler, range_checks, r_limbs, params);

    // Step 5: Range checks for q limbs and carries
    for i in 0..n {
        range_checks.entry(limb_bits).or_default().push(q[i]);
    }
    // Carry range: limb_bits + extra_bits + 1 (carry_offset_bits + 1)
    let carry_range_bits = carry_offset_bits + 1;
    for &c in &cu {
        range_checks.entry(carry_range_bits).or_default().push(c);
    }

    r_limbs
}

/// Proves r < p by decomposing (p-1) - r via borrow propagation.
pub fn less_than_p_check_multi(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    r: Limbs,
    params: &ModulusParams,
) {
    let n = r.len();
    let w1 = compiler.witness_one();
    let mut borrow_prev: Option<usize> = None;
    for i in 0..n {
        // Combine w1 terms to avoid duplicate column indices.
        let w1_coeff = if borrow_prev.is_some() {
            params.p_minus_1_limbs[i] + params.two_pow_w - FieldElement::ONE
        } else {
            params.p_minus_1_limbs[i] + params.two_pow_w
        };
        let mut terms = vec![
            SumTerm(Some(w1_coeff), w1),
            SumTerm(Some(-FieldElement::ONE), r[i]),
        ];
        if let Some(borrow) = borrow_prev {
            terms.push(SumTerm(None, borrow));
        }

        // borrow = floor(sum(terms) / 2^W)
        let borrow = compiler.num_witnesses();
        compiler.add_witness_builder(WitnessBuilder::SumQuotient {
            output:  borrow,
            terms:   terms.clone(),
            divisor: params.two_pow_w,
        });

        // Merged constraint: d[i] = sum(terms) - borrow * 2^W
        terms.push(SumTerm(Some(-params.two_pow_w), borrow));
        let d_i = compiler.add_sum(terms);

        // Range check r[i] and d[i]
        range_checks.entry(params.limb_bits).or_default().push(r[i]);
        range_checks.entry(params.limb_bits).or_default().push(d_i);

        borrow_prev = Some(borrow);
    }

    // Constrain final carry = 1 (valid r < p).
    if let Some(final_borrow) = borrow_prev {
        compiler.r1cs.add_constraint(
            &[(FieldElement::ONE, compiler.witness_one())],
            &[(FieldElement::ONE, final_borrow)],
            &[(FieldElement::ONE, compiler.witness_one())],
        );
    }
}

// ---------------------------------------------------------------------------
// Schoolbook column equations (shared by mul_mod_p_multi and non-native EC
// hints)
// ---------------------------------------------------------------------------

/// Merge terms with the same witness index by summing their coefficients.
fn merge_terms(terms: &[(FieldElement, usize)]) -> Vec<(FieldElement, usize)> {
    let mut map: BTreeMap<usize, FieldElement> = BTreeMap::new();
    for &(coeff, idx) in terms {
        *map.entry(idx).or_insert(FieldElement::ZERO) += coeff;
    }
    map.into_iter().map(|(idx, c)| (c, idx)).collect()
}

/// Witness indices for quotient and carry chain in column equations.
pub(in crate::msm) struct QuotientCarryWitnesses<'a> {
    pub q_pos:   &'a [usize],
    pub q_neg:   Option<&'a [usize]>,
    pub carries: &'a [usize],
}

/// Emit `2N-1` R1CS constraints verifying a schoolbook column equation
/// with unsigned-offset carry chain.
pub(in crate::msm) fn emit_schoolbook_column_equations(
    compiler: &mut NoirToR1CSCompiler,
    product_sets: &[(&[Vec<usize>], FieldElement)],
    linear_limbs: &[(&[usize], FieldElement)],
    qc: &QuotientCarryWitnesses,
    p_limbs: &[FieldElement],
    n: usize,
    limb_bits: u32,
    max_coeff_sum: u64,
) {
    let w1 = compiler.witness_one();
    let two_pow_w = FieldElement::from(2u64).pow([limb_bits as u64]);

    // Carry offset scaled for the merged equation's coefficients
    let extra_bits = ceil_log2(max_coeff_sum * n as u64) + 1;
    let carry_offset_bits = limb_bits + extra_bits;
    let carry_offset_fe = FieldElement::from(2u64).pow([carry_offset_bits as u64]);
    let offset_w = FieldElement::from(2u64).pow([(carry_offset_bits + limb_bits) as u64]);
    let offset_w_minus_carry = offset_w - carry_offset_fe;

    let num_columns = 2 * n - 1;

    for col in 0..num_columns {
        // LHS: Σ coeff * products[i][j] for i+j=col + Σ p[i]*q_neg[j] + carry_in +
        // offset
        let mut lhs_terms: Vec<(FieldElement, usize)> = Vec::new();

        for &(products, coeff) in product_sets {
            for i in 0..n {
                let j_val = col as isize - i as isize;
                if j_val >= 0 && (j_val as usize) < n {
                    lhs_terms.push((coeff, products[i][j_val as usize]));
                }
            }
        }

        // Add linear terms (for col < limbs.len() only)
        for &(limbs, coeff) in linear_limbs {
            if col < limbs.len() {
                lhs_terms.push((coeff, limbs[col]));
            }
        }

        // Add p*q_neg on the LHS (when using split quotients)
        if let Some(q_neg) = qc.q_neg {
            for i in 0..n {
                let j_val = col as isize - i as isize;
                if j_val >= 0 && (j_val as usize) < n {
                    lhs_terms.push((p_limbs[i], q_neg[j_val as usize]));
                }
            }
        }

        // Add carry_in and offset
        if col > 0 {
            lhs_terms.push((FieldElement::ONE, qc.carries[col - 1]));
            lhs_terms.push((offset_w_minus_carry, w1));
        } else {
            lhs_terms.push((offset_w, w1));
        }

        // RHS: Σ p[i]*q_pos[j] for i+j=col + carry_out * W (or offset at last column)
        let mut rhs_terms: Vec<(FieldElement, usize)> = Vec::new();
        for i in 0..n {
            let j_val = col as isize - i as isize;
            if j_val >= 0 && (j_val as usize) < n {
                rhs_terms.push((p_limbs[i], qc.q_pos[j_val as usize]));
            }
        }

        if col < num_columns - 1 {
            rhs_terms.push((two_pow_w, qc.carries[col]));
        } else {
            // Last column: balance with offset_w (no outgoing carry)
            rhs_terms.push((offset_w, w1));
        }

        // Merge terms with the same witness index (products may share cached witnesses)
        let lhs_merged = merge_terms(&lhs_terms);
        let rhs_merged = merge_terms(&rhs_terms);
        compiler
            .r1cs
            .add_constraint(&lhs_merged, &[(FieldElement::ONE, w1)], &rhs_merged);
    }
}
