//! N-limb modular arithmetic for EC field operations.
//!
//! Replaces both `ec_ops.rs` (N=1 path) and `wide_ops.rs` (N>1 path) with
//! unified multi-limb operations using `Limbs` (runtime-sized, Copy).

use {
    super::Limbs,
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField},
    provekit_common::{
        witness::{SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::collections::BTreeMap,
};

// ---------------------------------------------------------------------------
// N=1 single-limb path (moved from ec_ops.rs)
// ---------------------------------------------------------------------------

/// Reduce the value to given modulus (N=1 path).
/// Computes v = k*m + result, where 0 <= result < m.
pub fn reduce_mod_p(
    compiler: &mut NoirToR1CSCompiler,
    value: usize,
    modulus: FieldElement,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) -> usize {
    let m = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::Constant(
        provekit_common::witness::ConstantTerm(m, modulus),
    ));
    let k = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::IntegerQuotient(k, value, modulus));

    let k_mul_m = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::Product(k_mul_m, k, m));
    compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, k)], &[(FieldElement::ONE, m)], &[(
            FieldElement::ONE,
            k_mul_m,
        )]);

    let result = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::Sum(result, vec![
        SumTerm(Some(FieldElement::ONE), value),
        SumTerm(Some(-FieldElement::ONE), k_mul_m),
    ]));
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, k_mul_m), (FieldElement::ONE, result)],
        &[(FieldElement::ONE, value)],
    );

    let modulus_bits = modulus.into_bigint().num_bits();
    range_checks
        .entry(modulus_bits)
        .or_default()
        .push(result);

    result
}

/// a + b mod p (N=1 path)
pub fn add_mod_p_single(
    compiler: &mut NoirToR1CSCompiler,
    a: usize,
    b: usize,
    modulus: FieldElement,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) -> usize {
    let a_add_b = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::Sum(a_add_b, vec![
        SumTerm(Some(FieldElement::ONE), a),
        SumTerm(Some(FieldElement::ONE), b),
    ]));
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, a), (FieldElement::ONE, b)],
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, a_add_b)],
    );
    reduce_mod_p(compiler, a_add_b, modulus, range_checks)
}

/// a * b mod p (N=1 path)
pub fn mul_mod_p_single(
    compiler: &mut NoirToR1CSCompiler,
    a: usize,
    b: usize,
    modulus: FieldElement,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) -> usize {
    let a_mul_b = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::Product(a_mul_b, a, b));
    compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, a)], &[(FieldElement::ONE, b)], &[(
            FieldElement::ONE,
            a_mul_b,
        )]);
    reduce_mod_p(compiler, a_mul_b, modulus, range_checks)
}

/// (a - b) mod p (N=1 path)
pub fn sub_mod_p_single(
    compiler: &mut NoirToR1CSCompiler,
    a: usize,
    b: usize,
    modulus: FieldElement,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) -> usize {
    let a_sub_b = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::Sum(a_sub_b, vec![
        SumTerm(Some(FieldElement::ONE), a),
        SumTerm(Some(-FieldElement::ONE), b),
    ]));
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, a), (-FieldElement::ONE, b)],
        &[(FieldElement::ONE, a_sub_b)],
    );
    reduce_mod_p(compiler, a_sub_b, modulus, range_checks)
}

/// a^(-1) mod p (N=1 path)
pub fn inv_mod_p_single(
    compiler: &mut NoirToR1CSCompiler,
    a: usize,
    modulus: FieldElement,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) -> usize {
    let a_inv = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::ModularInverse(a_inv, a, modulus));

    let reduced = mul_mod_p_single(compiler, a, a_inv, modulus, range_checks);

    // Constrain reduced = 1
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, compiler.witness_one())],
        &[
            (FieldElement::ONE, reduced),
            (-FieldElement::ONE, compiler.witness_one()),
        ],
        &[(FieldElement::ZERO, compiler.witness_one())],
    );

    let mod_bits = modulus.into_bigint().num_bits();
    range_checks.entry(mod_bits).or_default().push(a_inv);

    a_inv
}

/// Checks if value is zero or not (used by all N values).
/// Returns a boolean witness: 1 if zero, 0 if non-zero.
///
/// Uses SafeInverse (not Inverse) because the input value may be zero.
/// SafeInverse outputs 0 when the input is 0, and is solved in the Other
/// layer (not batch-inverted), so zero inputs don't poison the batch.
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
    compiler.add_witness_builder(WitnessBuilder::Sum(
        is_zero,
        vec![
            SumTerm(Some(FieldElement::ONE), compiler.witness_one()),
            SumTerm(Some(-FieldElement::ONE), value_mul_value_inv),
        ],
    ));

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

/// (a + b) mod p for multi-limb values.
///
/// Per limb i: v_i = a[i] + b[i] + 2^W - q*p[i] + carry_{i-1}
///             carry_i = floor(v_i / 2^W)
///             r[i] = v_i - carry_i * 2^W
pub fn add_mod_p_multi(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    a: Limbs,
    b: Limbs,
    p_limbs: &[FieldElement],
    p_minus_1_limbs: &[FieldElement],
    two_pow_w: FieldElement,
    limb_bits: u32,
    modulus_raw: &[u64; 4],
) -> Limbs {
    let n = a.len();
    assert!(n >= 2, "add_mod_p_multi requires n >= 2, got n={n}");
    let w1 = compiler.witness_one();

    // Witness: q = floor((a + b) / p) ∈ {0, 1}
    let q = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::MultiLimbAddQuotient {
        output:    q,
        a_limbs:   a.as_slice().to_vec(),
        b_limbs:   b.as_slice().to_vec(),
        modulus:   *modulus_raw,
        limb_bits,
        num_limbs: n as u32,
    });
    // q is boolean
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, q)],
        &[(FieldElement::ONE, q)],
        &[(FieldElement::ONE, q)],
    );

    let mut r = Limbs::new(n);
    let mut carry_prev: Option<usize> = None;

    for i in 0..n {
        // v_offset = a[i] + b[i] + 2^W - q*p[i] + carry_{i-1}
        let mut terms = vec![
            SumTerm(None, a[i]),
            SumTerm(None, b[i]),
            SumTerm(Some(two_pow_w), w1),
            SumTerm(Some(-p_limbs[i]), q),
        ];
        if let Some(carry) = carry_prev {
            terms.push(SumTerm(None, carry));
            // Compensate for previous 2^W offset
            terms.push(SumTerm(Some(-FieldElement::ONE), w1));
        }
        let v_offset = compiler.add_sum(terms);

        // carry = floor(v_offset / 2^W)
        let carry = compiler.num_witnesses();
        compiler.add_witness_builder(WitnessBuilder::IntegerQuotient(
            carry, v_offset, two_pow_w,
        ));
        // r[i] = v_offset - carry * 2^W
        r[i] = compiler.add_sum(vec![
            SumTerm(None, v_offset),
            SumTerm(Some(-two_pow_w), carry),
        ]);
        carry_prev = Some(carry);
    }

    less_than_p_check_multi(compiler, range_checks, r, p_minus_1_limbs, two_pow_w, limb_bits);

    r
}

/// (a - b) mod p for multi-limb values.
pub fn sub_mod_p_multi(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    a: Limbs,
    b: Limbs,
    p_limbs: &[FieldElement],
    p_minus_1_limbs: &[FieldElement],
    two_pow_w: FieldElement,
    limb_bits: u32,
    modulus_raw: &[u64; 4],
) -> Limbs {
    let n = a.len();
    assert!(n >= 2, "sub_mod_p_multi requires n >= 2, got n={n}");
    let w1 = compiler.witness_one();

    // Witness: q = (a < b) ? 1 : 0
    let q = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::MultiLimbSubBorrow {
        output:    q,
        a_limbs:   a.as_slice().to_vec(),
        b_limbs:   b.as_slice().to_vec(),
        modulus:   *modulus_raw,
        limb_bits,
        num_limbs: n as u32,
    });
    // q is boolean
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, q)],
        &[(FieldElement::ONE, q)],
        &[(FieldElement::ONE, q)],
    );

    let mut r = Limbs::new(n);
    let mut carry_prev: Option<usize> = None;

    for i in 0..n {
        // v_offset = a[i] - b[i] + q*p[i] + 2^W + carry_{i-1}
        let mut terms = vec![
            SumTerm(None, a[i]),
            SumTerm(Some(-FieldElement::ONE), b[i]),
            SumTerm(Some(p_limbs[i]), q),
            SumTerm(Some(two_pow_w), w1),
        ];
        if let Some(carry) = carry_prev {
            terms.push(SumTerm(None, carry));
            terms.push(SumTerm(Some(-FieldElement::ONE), w1));
        }
        let v_offset = compiler.add_sum(terms);

        let carry = compiler.num_witnesses();
        compiler.add_witness_builder(WitnessBuilder::IntegerQuotient(
            carry, v_offset, two_pow_w,
        ));
        r[i] = compiler.add_sum(vec![
            SumTerm(None, v_offset),
            SumTerm(Some(-two_pow_w), carry),
        ]);
        carry_prev = Some(carry);
    }

    less_than_p_check_multi(compiler, range_checks, r, p_minus_1_limbs, two_pow_w, limb_bits);

    r
}

/// (a * b) mod p for multi-limb values using schoolbook multiplication.
///
/// Verifies: a·b = p·q + r in base W = 2^limb_bits.
/// Column k: Σ_{i+j=k} a[i]*b[j] + carry_{k-1} + OFFSET
///         = Σ_{i+j=k} p[i]*q[j] + r[k] + carry_k * W
pub fn mul_mod_p_multi(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    a: Limbs,
    b: Limbs,
    p_limbs: &[FieldElement],
    p_minus_1_limbs: &[FieldElement],
    two_pow_w: FieldElement,
    limb_bits: u32,
    modulus_raw: &[u64; 4],
) -> Limbs {
    let n = a.len();
    assert!(n >= 2, "mul_mod_p_multi requires n >= 2, got n={n}");

    // Soundness check: column equation values must not overflow the native field.
    // The maximum value across either side of any column equation is bounded by
    // 2^(2*limb_bits + ceil(log2(n)) + 3). This must be strictly less than the
    // native field modulus p >= 2^(MODULUS_BIT_SIZE - 1).
    {
        let ceil_log2_n = (n as f64).log2().ceil() as u32;
        let max_bits = 2 * limb_bits + ceil_log2_n + 3;
        assert!(
            max_bits < FieldElement::MODULUS_BIT_SIZE,
            "Schoolbook column equation overflow: limb_bits={limb_bits}, n={n} limbs \
             requires {max_bits} bits, but native field is only {} bits. \
             Use smaller limb_bits.",
            FieldElement::MODULUS_BIT_SIZE,
        );
    }

    let w1 = compiler.witness_one();
    let num_carries = 2 * n - 2;
    // Carry offset: 2^(limb_bits + ceil(log2(n)) + 1)
    let extra_bits = ((n as f64).log2().ceil() as u32) + 1;
    let carry_offset_bits = limb_bits + extra_bits;
    let carry_offset_fe = FieldElement::from(2u64).pow([carry_offset_bits as u64]);
    // offset_w = carry_offset * 2^limb_bits
    let offset_w = FieldElement::from(2u64).pow([(carry_offset_bits + limb_bits) as u64]);
    // offset_w_minus_carry = offset_w - carry_offset = carry_offset * (2^limb_bits - 1)
    let offset_w_minus_carry = offset_w - carry_offset_fe;

    // Step 1: Allocate hint witnesses (q limbs, r limbs, carries)
    let os = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::MultiLimbMulModHint {
        output_start: os,
        a_limbs:      a.as_slice().to_vec(),
        b_limbs:      b.as_slice().to_vec(),
        modulus:      *modulus_raw,
        limb_bits,
        num_limbs:    n as u32,
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
    for k in 0..(2 * n - 1) {
        // LHS: Σ_{i+j=k} a[i]*b[j] + carry_{k-1} + OFFSET
        let mut lhs_terms: Vec<(FieldElement, usize)> = Vec::new();
        for i in 0..n {
            let j_val = k as isize - i as isize;
            if j_val >= 0 && (j_val as usize) < n {
                lhs_terms.push((FieldElement::ONE, ab_products[i][j_val as usize]));
            }
        }
        // Add carry_{k-1}
        if k > 0 {
            lhs_terms.push((FieldElement::ONE, cu[k - 1]));
            // Add offset_w - carry_offset for subsequent columns
            lhs_terms.push((offset_w_minus_carry, w1));
        } else {
            // First column: add offset_w
            lhs_terms.push((offset_w, w1));
        }

        // RHS: Σ_{i+j=k} p[i]*q[j] + r[k] + carry_k * W
        let mut rhs_terms: Vec<(FieldElement, usize)> = Vec::new();
        for i in 0..n {
            let j_val = k as isize - i as isize;
            if j_val >= 0 && (j_val as usize) < n {
                rhs_terms.push((p_limbs[i], q[j_val as usize]));
            }
        }
        if k < n {
            rhs_terms.push((FieldElement::ONE, r_indices[k]));
        }
        if k < 2 * n - 2 {
            rhs_terms.push((two_pow_w, cu[k]));
        } else {
            // Last column: RHS includes offset_w to balance the LHS offset
            // LHS has: carry[k-1] + offset_w_minus_carry = true_carry + offset_w
            // RHS needs: sum_pq[k] + offset_w (no outgoing carry at last column)
            rhs_terms.push((offset_w, w1));
        }

        compiler
            .r1cs
            .add_constraint(&lhs_terms, &[(FieldElement::ONE, w1)], &rhs_terms);
    }

    // Step 4: less-than-p check and range checks on r
    let mut r_limbs = Limbs::new(n);
    for (i, &ri) in r_indices.iter().enumerate() {
        r_limbs[i] = ri;
    }
    less_than_p_check_multi(compiler, range_checks, r_limbs, p_minus_1_limbs, two_pow_w, limb_bits);

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

/// a^(-1) mod p for multi-limb values.
/// Uses MultiLimbModularInverse hint, verifies via mul_mod_p(a, inv) = [1, 0, ..., 0].
pub fn inv_mod_p_multi(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    a: Limbs,
    p_limbs: &[FieldElement],
    p_minus_1_limbs: &[FieldElement],
    two_pow_w: FieldElement,
    limb_bits: u32,
    modulus_raw: &[u64; 4],
) -> Limbs {
    let n = a.len();
    assert!(n >= 2, "inv_mod_p_multi requires n >= 2, got n={n}");

    // Hint: compute inverse
    let inv_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::MultiLimbModularInverse {
        output_start: inv_start,
        a_limbs:      a.as_slice().to_vec(),
        modulus:      *modulus_raw,
        limb_bits,
        num_limbs:    n as u32,
    });
    let mut inv = Limbs::new(n);
    for i in 0..n {
        inv[i] = inv_start + i;
    }

    // Verify: a * inv mod p = [1, 0, ..., 0]
    let product = mul_mod_p_multi(
        compiler,
        range_checks,
        a,
        inv,
        p_limbs,
        p_minus_1_limbs,
        two_pow_w,
        limb_bits,
        modulus_raw,
    );

    // Constrain product[0] = 1
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, product[0])],
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, compiler.witness_one())],
    );
    // Constrain product[1..n] = 0
    for i in 1..n {
        compiler.r1cs.add_constraint(
            &[(FieldElement::ONE, product[i])],
            &[(FieldElement::ONE, compiler.witness_one())],
            &[],
        );
    }

    inv
}

/// Proves r < p by decomposing (p-1) - r into non-negative multi-limb values.
/// Uses borrow propagation: d[i] = (p-1)[i] - r[i] + borrow_in - borrow_out * 2^W
fn less_than_p_check_multi(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    r: Limbs,
    p_minus_1_limbs: &[FieldElement],
    two_pow_w: FieldElement,
    limb_bits: u32,
) {
    let n = r.len();
    let w1 = compiler.witness_one();
    let mut borrow_prev: Option<usize> = None;

    for i in 0..n {
        // v_diff = (p-1)[i] + 2^W - r[i] + borrow_prev
        let p_minus_1_plus_offset = p_minus_1_limbs[i] + two_pow_w;
        let mut terms = vec![
            SumTerm(Some(p_minus_1_plus_offset), w1),
            SumTerm(Some(-FieldElement::ONE), r[i]),
        ];
        if let Some(borrow) = borrow_prev {
            terms.push(SumTerm(None, borrow));
            terms.push(SumTerm(Some(-FieldElement::ONE), w1));
        }
        let v_diff = compiler.add_sum(terms);

        // borrow = floor(v_diff / 2^W)
        let borrow = compiler.num_witnesses();
        compiler.add_witness_builder(WitnessBuilder::IntegerQuotient(
            borrow, v_diff, two_pow_w,
        ));
        // d[i] = v_diff - borrow * 2^W
        let d_i = compiler.add_sum(vec![
            SumTerm(None, v_diff),
            SumTerm(Some(-two_pow_w), borrow),
        ]);

        // Range check r[i] and d[i]
        range_checks.entry(limb_bits).or_default().push(r[i]);
        range_checks.entry(limb_bits).or_default().push(d_i);

        borrow_prev = Some(borrow);
    }

    // Constrain final borrow = 0: if borrow_out != 0, then r > p-1 (i.e. r >= p),
    // which would mean the result is not properly reduced.
    if let Some(final_borrow) = borrow_prev {
        compiler.r1cs.add_constraint(
            &[(FieldElement::ONE, compiler.witness_one())],
            &[(FieldElement::ONE, final_borrow)],
            &[(FieldElement::ZERO, compiler.witness_one())],
        );
    }
}
