use {
    crate::{
        msm::curve::{CurveParams, Limb2},
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::Field,
    provekit_common::{
        witness::{SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::collections::BTreeMap,
};

/// (a + b) mod p for 256-bit values in two 128-bit limbs.
///
/// Equation: a + b = q * p + r, where q ∈ {0, 1}, 0 ≤ r < p.
///
/// Uses the offset trick to avoid negative intermediate values:
///   v_offset = a_lo + b_lo + 2^128 - q * p_lo  (always ≥ 0)
///   carry_offset = floor(v_offset / 2^128) ∈ {0, 1, 2}
///   r_lo = v_offset - carry_offset * 2^128
///   r_hi = a_hi + b_hi + carry_offset - 1 - q * p_hi
///
/// Less-than-p check (proves r < p):
///   d_lo + d_hi * 2^128 = (p - 1) - r  (all components ≥ 0)
///
/// Constraints (7 total):
///   1. q is boolean:  q * q = q
///   2-3. Column 0: v_offset defined, then r_lo = v_offset - carry_offset *
/// 2^128
///   4. Column 1: r_hi = a_hi + b_hi + carry_offset - 1 - q * p_hi
///   5-6. LT check: v_diff defined, then d_lo = v_diff - borrow_compl * 2^128
///   7. LT check: d_hi = (p_hi - 1) + borrow_compl - r_hi
///
/// Range checks: r_lo, r_hi, d_lo, d_hi (128-bit each)
pub fn add_mod_p(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    a: Limb2,
    b: Limb2,
    params: &CurveParams,
) -> Limb2 {
    let two_128 = FieldElement::from(2u64).pow([128u64]);
    let p_lo_fe = params.p_lo_fe();
    let p_hi_fe = params.p_hi_fe();
    let w1 = compiler.witness_one();

    // Witness: q = floor((a + b) / p) ∈ {0, 1}
    // -----------------------------------------------------------
    let q = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::WideAddQuotient {
        output:  q,
        a_lo:    a.lo,
        a_hi:    a.hi,
        b_lo:    b.lo,
        b_hi:    b.hi,
        modulus: params.field_modulus_p,
    });
    // constraining q to be boolean
    compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, q)], &[(FieldElement::ONE, q)], &[(
            FieldElement::ONE,
            q,
        )]);

    // Computing r_lo: lower 128 bits of result
    // -----------------------------------------------------------
    // v_offset = a_lo + b_lo + 2^128 - q * p_lo
    // (2^128 offset ensures v_offset is always non-negative)
    let v_offset = compiler.add_sum(vec![
        SumTerm(None, a.lo),
        SumTerm(None, b.lo),
        SumTerm(Some(two_128), w1),
        SumTerm(Some(-p_lo_fe), q),
    ]);
    // computing carry_offset = floor(v_offset / 2^128)
    let carry_offset = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::IntegerQuotient(
        carry_offset,
        v_offset,
        two_128,
    ));
    // computing r_lo = v_offset - carry_offset * 2^128
    let r_lo = compiler.add_sum(vec![
        SumTerm(None, v_offset),
        SumTerm(Some(-two_128), carry_offset),
    ]);

    // Computing r_hi: upper 128 bits of result
    // -----------------------------------------------------------
    // r_hi = a_hi + b_hi + carry_offset - 1 - q * p_hi
    // (-1 compensates for the 2^128 offset added in the low column)
    let r_hi = compiler.add_sum(vec![
        SumTerm(None, a.hi),
        SumTerm(None, b.hi),
        SumTerm(None, carry_offset),
        SumTerm(Some(-FieldElement::ONE), w1),
        SumTerm(Some(-p_hi_fe), q),
    ]);

    less_than_p_check(compiler, range_checks, r_lo, r_hi, params);

    Limb2 { lo: r_lo, hi: r_hi }
}

/// (a - b) mod p for 256-bit values in two 128-bit limbs.
///
/// Equation: a - b + q * p = r, where q ∈ {0, 1}, 0 ≤ r < p.
///   q = 0 if a ≥ b (result is non-negative without correction)
///   q = 1 if a < b (add p to make result non-negative)
///
/// Uses the offset trick to avoid negative intermediate values:
///   v_offset = a_lo - b_lo + q * p_lo + 2^128  (always ≥ 0)
///   carry_offset = floor(v_offset / 2^128) ∈ {0, 1, 2}
///   r_lo = v_offset - carry_offset * 2^128
///   r_hi = a_hi - b_hi + q * p_hi + carry_offset - 1
///
/// Less-than-p check (proves r < p):
///   d_lo + d_hi * 2^128 = (p - 1) - r  (all components ≥ 0)
///
/// Constraints (7 total):
///   1. q is boolean:  q * q = q
///   2-3. Column 0: v_offset defined, then r_lo = v_offset - carry_offset *
/// 2^128
///   4. Column 1: r_hi = a_hi - b_hi + q * p_hi + carry_offset - 1
///   5-6. LT check: v_diff defined, then d_lo = v_diff - borrow_compl * 2^128
///   7. LT check: d_hi = (p_hi - 1) + borrow_compl - r_hi
///
/// Range checks: r_lo, r_hi, d_lo, d_hi (128-bit each)
pub fn sub_mod_p(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    a: Limb2,
    b: Limb2,
    params: &CurveParams,
) -> Limb2 {
    let two_128 = FieldElement::from(2u64).pow([128u64]);
    let p_lo_fe = params.p_lo_fe();
    let p_hi_fe = params.p_hi_fe();
    let w1 = compiler.witness_one();

    // Witness: q = (a < b) ? 1 : 0
    // -----------------------------------------------------------
    let q = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::WideSubBorrow {
        output: q,
        a_lo:   a.lo,
        a_hi:   a.hi,
        b_lo:   b.lo,
        b_hi:   b.hi,
    });
    // constraining q to be boolean
    compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, q)], &[(FieldElement::ONE, q)], &[(
            FieldElement::ONE,
            q,
        )]);

    // Computing r_lo: lower 128 bits of result
    // -----------------------------------------------------------
    // v_offset = a_lo - b_lo + q * p_lo + 2^128
    // (2^128 offset ensures v_offset is always non-negative)
    let v_offset = compiler.add_sum(vec![
        SumTerm(None, a.lo),
        SumTerm(Some(-FieldElement::ONE), b.lo),
        SumTerm(Some(p_lo_fe), q),
        SumTerm(Some(two_128), w1),
    ]);
    // computing carry_offset = floor(v_offset / 2^128)
    let carry_offset = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::IntegerQuotient(
        carry_offset,
        v_offset,
        two_128,
    ));
    // computing r_lo = v_offset - carry_offset * 2^128
    let r_lo = compiler.add_sum(vec![
        SumTerm(None, v_offset),
        SumTerm(Some(-two_128), carry_offset),
    ]);

    // Computing r_hi: upper 128 bits of result
    // -----------------------------------------------------------
    // r_hi = a_hi - b_hi + q * p_hi + carry_offset - 1
    // (-1 compensates for the 2^128 offset added in the low column)
    let r_hi = compiler.add_sum(vec![
        SumTerm(None, a.hi),
        SumTerm(Some(-FieldElement::ONE), b.hi),
        SumTerm(Some(p_hi_fe), q),
        SumTerm(None, carry_offset),
        SumTerm(Some(-FieldElement::ONE), w1),
    ]);

    less_than_p_check(compiler, range_checks, r_lo, r_hi, params);

    Limb2 { lo: r_lo, hi: r_hi }
}

/// (a × b) mod p for 256-bit values in two 128-bit limbs.
///
/// Verifies the integer identity `a * b = p * q + r` using schoolbook
/// multiplication in base W = 2^86 (86-bit limbs ensure all column
/// products < 2^172 ≪ BN254_r ≈ 2^254, so field equations = integer equations).
///
/// Three layers of verification:
///   1. Decomposition links: prove 86-bit witnesses match the 128-bit
///      inputs/outputs
///   2. Column equations:    prove a86 * b86 = p86 * q86 + r86 (integer)
///   3. Less-than-p check:   prove r < p
///
/// Witness layout (MulModHint, 20 witnesses at output_start):
///   [0..2)   q_lo, q_hi     — quotient 128-bit limbs (unconstrained)
///   [2..4)   r_lo, r_hi     — remainder 128-bit limbs (OUTPUT)
///   [4..7)   a86_0..2       — a in 86-bit limbs
///   [7..10)  b86_0..2       — b in 86-bit limbs
///   [10..13) q86_0..2       — q in 86-bit limbs
///   [13..16) r86_0..2       — r in 86-bit limbs
///   [16..20) c0u..c3u       — unsigned-offset carries (c_signed + 2^88)
///
/// Constraints (26 total):
///   9 decomposition links (a, b, r × 3 each)
///   9 product witnesses (a_i × b_j)
///   5 column equations
///   3 less-than-p check
///
/// Range checks (23 total):
///   128-bit: r_lo, r_hi, d_lo, d_hi
///   86-bit:  a86_0, a86_1, b86_0, b86_1, q86_0, q86_1, r86_0, r86_1
///   84-bit:  a86_2, b86_2, q86_2, r86_2
///   89-bit:  c0u, c1u, c2u, c3u
///   44-bit:  carry_a, carry_b, carry_r
pub fn mul_mod_p(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    a: Limb2,
    b: Limb2,
    params: &CurveParams,
) -> Limb2 {
    let two_44 = FieldElement::from(2u64).pow([44u64]);
    let two_86 = FieldElement::from(2u64).pow([86u64]);
    let two_128 = FieldElement::from(2u64).pow([128u64]);
    let offset_fe = FieldElement::from(2u64).pow([88u64]); // CARRY_OFFSET
    let offset_w = FieldElement::from(2u64).pow([174u64]); // 2^88 * 2^86
    let offset_w_minus_1 = offset_w - offset_fe; // 2^88 * (2^86 - 1)
    let [p0, p1, p2] = params.p_86_limbs();
    let w1 = compiler.witness_one();

    // Step 1: Allocate MulModHint (20 witnesses)
    // -----------------------------------------------------------
    let os = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::MulModHint {
        output_start: os,
        a_lo:         a.lo,
        a_hi:         a.hi,
        b_lo:         b.lo,
        b_hi:         b.hi,
        modulus:      params.field_modulus_p,
    });

    // Witness indices
    let r_lo = os + 2;
    let r_hi = os + 3;
    let a86 = [os + 4, os + 5, os + 6];
    let b86 = [os + 7, os + 8, os + 9];
    let q86 = [os + 10, os + 11, os + 12];
    let r86 = [os + 13, os + 14, os + 15];
    let cu = [os + 16, os + 17, os + 18, os + 19];

    // Step 2: Decomposition consistency for a, b, r
    // -----------------------------------------------------------
    decompose_check(
        compiler,
        range_checks,
        a.lo,
        a.hi,
        a86,
        two_86,
        two_44,
        two_128,
        w1,
    );
    decompose_check(
        compiler,
        range_checks,
        b.lo,
        b.hi,
        b86,
        two_86,
        two_44,
        two_128,
        w1,
    );
    decompose_check(
        compiler,
        range_checks,
        r_lo,
        r_hi,
        r86,
        two_86,
        two_44,
        two_128,
        w1,
    );

    // Step 3: Product witnesses (9 R1CS constraints)
    // -----------------------------------------------------------
    let ab00 = compiler.add_product(a86[0], b86[0]);
    let ab01 = compiler.add_product(a86[0], b86[1]);
    let ab10 = compiler.add_product(a86[1], b86[0]);
    let ab02 = compiler.add_product(a86[0], b86[2]);
    let ab11 = compiler.add_product(a86[1], b86[1]);
    let ab20 = compiler.add_product(a86[2], b86[0]);
    let ab12 = compiler.add_product(a86[1], b86[2]);
    let ab21 = compiler.add_product(a86[2], b86[1]);
    let ab22 = compiler.add_product(a86[2], b86[2]);

    // Step 4: Column equations (5 R1CS constraints)
    // -----------------------------------------------------------
    // Identity: a*b = p*q + r in base W=2^86.
    // Carries stored with unsigned offset: cu_i = c_i + 2^88.
    //
    // col0: ab00 + 2^174                      = p0*q0 + r0 + W*cu0
    // col1: ab01 + ab10 + cu0 + (2^174-2^88)  = p0*q1 + p1*q0 + r1 + W*cu1
    // col2: ab02+ab11+ab20 + cu1 + (2^174-2^88) = p0*q2+p1*q1+p2*q0 + r2 + W*cu2
    // col3: ab12 + ab21 + cu2 + (2^174-2^88)  = p1*q2 + p2*q1 + W*cu3
    // col4: ab22 + cu3                         = p2*q2 + 2^88

    // col0
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, ab00), (offset_w, w1)],
        &[(FieldElement::ONE, w1)],
        &[(p0, q86[0]), (FieldElement::ONE, r86[0]), (two_86, cu[0])],
    );

    // col1
    compiler.r1cs.add_constraint(
        &[
            (FieldElement::ONE, ab01),
            (FieldElement::ONE, ab10),
            (FieldElement::ONE, cu[0]),
            (offset_w_minus_1, w1),
        ],
        &[(FieldElement::ONE, w1)],
        &[
            (p0, q86[1]),
            (p1, q86[0]),
            (FieldElement::ONE, r86[1]),
            (two_86, cu[1]),
        ],
    );

    // col2
    compiler.r1cs.add_constraint(
        &[
            (FieldElement::ONE, ab02),
            (FieldElement::ONE, ab11),
            (FieldElement::ONE, ab20),
            (FieldElement::ONE, cu[1]),
            (offset_w_minus_1, w1),
        ],
        &[(FieldElement::ONE, w1)],
        &[
            (p0, q86[2]),
            (p1, q86[1]),
            (p2, q86[0]),
            (FieldElement::ONE, r86[2]),
            (two_86, cu[2]),
        ],
    );

    // col3
    compiler.r1cs.add_constraint(
        &[
            (FieldElement::ONE, ab12),
            (FieldElement::ONE, ab21),
            (FieldElement::ONE, cu[2]),
            (offset_w_minus_1, w1),
        ],
        &[(FieldElement::ONE, w1)],
        &[(p1, q86[2]), (p2, q86[1]), (two_86, cu[3])],
    );

    // col4
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, ab22), (FieldElement::ONE, cu[3])],
        &[(FieldElement::ONE, w1)],
        &[(p2, q86[2]), (offset_fe, w1)],
    );

    // Step 5: Less-than-p check (r < p) + 128-bit range checks on r_lo, r_hi
    // -----------------------------------------------------------
    less_than_p_check(compiler, range_checks, r_lo, r_hi, params);

    // Step 6: Range checks (mul-specific)
    // -----------------------------------------------------------
    // 86-bit: limbs 0 and 1 of a, b, q, r
    for &idx in &[
        a86[0], a86[1], b86[0], b86[1], q86[0], q86[1], r86[0], r86[1],
    ] {
        range_checks.entry(86).or_default().push(idx);
    }

    // 84-bit: limb 2 of a, b, q, r (bits [172..256) = 84 bits)
    for &idx in &[a86[2], b86[2], q86[2], r86[2]] {
        range_checks.entry(84).or_default().push(idx);
    }

    // 89-bit: unsigned-offset carries (|c_signed| < 2^88, so c_unsigned ∈ [0,
    // 2^89))
    for &idx in &cu {
        range_checks.entry(89).or_default().push(idx);
    }

    Limb2 { lo: r_lo, hi: r_hi }
}

/// a^(-1) mod p for 256-bit values in two 128-bit limbs.
///
/// Hint-and-verify pattern:
///   1. Prover computes inv = a^(p-2) mod p  (Fermat's little theorem)
///   2. Circuit verifies a * inv mod p = 1
///
/// Constraints: 26 from mul_mod_p + 2 equality checks = 28 total.
pub fn inv_mod_p(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    value: Limb2,
    params: &CurveParams,
) -> Limb2 {
    // Witness: inv = a^(-1) mod p (2 witnesses: lo, hi)
    // -----------------------------------------------------------
    let value_inv = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::WideModularInverse {
        output_start: value_inv,
        a_lo:         value.lo,
        a_hi:         value.hi,
        modulus:      params.field_modulus_p,
    });
    let inv = Limb2 {
        lo: value_inv,
        hi: value_inv + 1,
    };

    // Verifying a * inv mod p = 1
    // -----------------------------------------------------------
    // computing product = value * inv mod p
    let product = mul_mod_p(compiler, range_checks, value, inv, params);
    // constraining product_lo = 1  (because 1 = 1 + 0 * 2^128)
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, product.lo)],
        &[(FieldElement::ONE, compiler.witness_one())],
        &[(FieldElement::ONE, compiler.witness_one())],
    );
    // constraining product_hi = 0
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, product.hi)],
        &[(FieldElement::ONE, compiler.witness_one())],
        &[],
    );

    inv
}

/// Verify that 128-bit limbs (v_lo, v_hi) decompose into 86-bit limbs (v86).
///
/// Equations:
///   v_lo = v86_0 + v86_1 * 2^86 - carry * 2^128
///   v_hi = carry + v86_2 * 2^44
///
/// All intermediate values < 2^172 ≪ BN254_r, so field equations = integer
/// equations.
///
/// Creates: 1 intermediate witness (v_sum), 1 carry witness (IntegerQuotient).
/// Adds: 3 R1CS constraints (v_sum definition + 2 decomposition checks).
/// Range checks: carry (44-bit).
/// Proves r < p by decomposing (p - 1) - r into non-negative 128-bit limbs.
///
/// If d_lo, d_hi >= 0 then (p - 1) - r >= 0, i.e. r <= p - 1 < p.
/// Uses the 2^128 offset trick to avoid negative intermediate values.
///
/// Range checks r_lo, r_hi, d_lo, d_hi (128-bit each).
fn less_than_p_check(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    r_lo: usize,
    r_hi: usize,
    params: &CurveParams,
) {
    let two_128 = FieldElement::from(2u64).pow([128u64]);
    let p_lo_fe = params.p_lo_fe();
    let p_hi_fe = params.p_hi_fe();
    let w1 = compiler.witness_one();

    // v_diff = (p_lo - 1) + 2^128 - r_lo
    // (2^128 offset ensures v_diff is always non-negative)
    let p_lo_minus_1_plus_offset = p_lo_fe - FieldElement::ONE + two_128;
    let v_diff = compiler.add_sum(vec![
        SumTerm(Some(p_lo_minus_1_plus_offset), w1),
        SumTerm(Some(-FieldElement::ONE), r_lo),
    ]);
    // borrow_compl = floor(v_diff / 2^128)
    let borrow_compl = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::IntegerQuotient(
        borrow_compl,
        v_diff,
        two_128,
    ));
    // d_lo = v_diff - borrow_compl * 2^128
    let d_lo = compiler.add_sum(vec![
        SumTerm(None, v_diff),
        SumTerm(Some(-two_128), borrow_compl),
    ]);
    // d_hi = (p_hi - 1) + borrow_compl - r_hi
    let d_hi = compiler.add_sum(vec![
        SumTerm(Some(p_hi_fe - FieldElement::ONE), w1),
        SumTerm(None, borrow_compl),
        SumTerm(Some(-FieldElement::ONE), r_hi),
    ]);

    // Range checks (128-bit)
    range_checks.entry(128).or_default().push(r_lo);
    range_checks.entry(128).or_default().push(r_hi);
    range_checks.entry(128).or_default().push(d_lo);
    range_checks.entry(128).or_default().push(d_hi);
}

fn decompose_check(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    v_lo: usize,
    v_hi: usize,
    v86: [usize; 3],
    two_86: FieldElement,
    two_44: FieldElement,
    two_128: FieldElement,
    w1: usize,
) {
    // v_sum = v86_0 + v86_1 * 2^86 (intermediate for IntegerQuotient)
    let v_sum = compiler.add_sum(vec![SumTerm(None, v86[0]), SumTerm(Some(two_86), v86[1])]);

    // carry = floor(v_sum / 2^128)  ∈ [0, 2^44)
    let carry = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::IntegerQuotient(carry, v_sum, two_128));

    // Low check: v_sum - carry * 2^128 = v_lo
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, v_sum), (-two_128, carry)],
        &[(FieldElement::ONE, w1)],
        &[(FieldElement::ONE, v_lo)],
    );

    // High check: carry + v86_2 * 2^44 = v_hi
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, carry), (two_44, v86[2])],
        &[(FieldElement::ONE, w1)],
        &[(FieldElement::ONE, v_hi)],
    );

    // Range check carry (44-bit)
    range_checks.entry(44).or_default().push(carry);
}
