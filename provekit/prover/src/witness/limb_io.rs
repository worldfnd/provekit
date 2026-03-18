//! Limb I/O helpers for multi-limb witness solving.
//!
//! These functions read/write u128 limb values from/to the witness array
//! and solve schoolbook column equations (quotient + carry computation).

use {
    crate::{
        bigint_mod::{decompose_to_u128_limbs, reconstruct_from_u128_limbs, signed_quotient_wide},
        ec_arith::compute_ec_verification_carries,
    },
    ark_ff::{BigInt, PrimeField},
    provekit_common::FieldElement,
};

/// Convert a u128 value to a FieldElement.
pub(super) fn u128_to_fe(val: u128) -> FieldElement {
    FieldElement::from_bigint(BigInt([val as u64, (val >> 64) as u64, 0, 0])).unwrap()
}

/// Read witness limbs and reconstruct as [u64; 4].
pub(super) fn read_witness_limbs(
    witness: &[Option<FieldElement>],
    indices: &[usize],
    limb_bits: u32,
) -> [u64; 4] {
    let limb_values: Vec<u128> = indices
        .iter()
        .map(|&idx| {
            assert!(
                idx < witness.len(),
                "read_witness_limbs: index {idx} out of bounds (witness len {})",
                witness.len()
            );
            let bigint = witness[idx].unwrap().into_bigint().0;
            bigint[0] as u128 | ((bigint[1] as u128) << 64)
        })
        .collect();
    reconstruct_from_u128_limbs(&limb_values, limb_bits)
}

/// Write u128 limb values as FieldElement witnesses starting at `start`.
pub(super) fn write_limbs(witness: &mut [Option<FieldElement>], start: usize, vals: &[u128]) {
    for (i, &val) in vals.iter().enumerate() {
        witness[start + i] = Some(u128_to_fe(val));
    }
}

/// Split a signed quotient into `(q_pos, q_neg)` limb vectors.
pub(super) fn split_quotient(q_abs: Vec<u128>, is_neg: bool, n: usize) -> (Vec<u128>, Vec<u128>) {
    if is_neg {
        (vec![0u128; n], q_abs)
    } else {
        (q_abs, vec![0u128; n])
    }
}

/// Field modulus and limb configuration for a column equation.
pub(super) struct ColumnEqParams<'a> {
    pub num_limbs:       usize,
    pub limb_bits:       u32,
    pub max_coeff_sum:   u64,
    pub field_modulus_p: &'a [u64; 4],
    pub p_limbs:         &'a [u128],
}

/// LHS/RHS terms defining a schoolbook column equation.
pub(super) struct ColumnEqTerms<'a> {
    pub lhs_products:   &'a [(&'a [u64; 4], &'a [u64; 4], u64)],
    pub rhs_products:   &'a [(&'a [u64; 4], &'a [u64; 4], u64)],
    pub lhs_linear:     &'a [(&'a [u64; 4], u64)],
    pub rhs_linear:     &'a [(&'a [u64; 4], u64)],
    pub carry_products: &'a [(&'a [u128], &'a [u128], i64)],
    pub carry_linear:   &'a [(Vec<i128>, i64)],
}

/// Solve one column equation: quotient -> split -> write -> carries -> write.
///
/// Computes `(LHS - RHS) / p` as a signed quotient, splits into (q_pos, q_neg),
/// computes verification carries, and writes all witnesses at `output_start +
/// offset`. Witness layout at offset: `[q_pos(N), q_neg(N), carries(2N-2)]`.
pub(super) fn solve_and_write_equation(
    witness: &mut [Option<FieldElement>],
    output_start: usize,
    offset: usize,
    params: &ColumnEqParams,
    terms: &ColumnEqTerms,
) {
    let n = params.num_limbs;
    let (q_abs, is_neg) = signed_quotient_wide(
        terms.lhs_products,
        terms.rhs_products,
        terms.lhs_linear,
        terms.rhs_linear,
        params.field_modulus_p,
        n,
        params.limb_bits,
    );
    let (q_pos, q_neg) = split_quotient(q_abs, is_neg, n);
    write_limbs(witness, output_start + offset, &q_pos);
    write_limbs(witness, output_start + offset + n, &q_neg);
    let carries = compute_ec_verification_carries(
        terms.carry_products,
        terms.carry_linear,
        params.p_limbs,
        &q_pos,
        &q_neg,
        n,
        params.limb_bits,
        params.max_coeff_sum,
    );
    write_limbs(witness, output_start + offset + 2 * n, &carries);
}

/// Decomposed values for a 3-equation EC hint (Double or Add).
pub(super) struct EcHint3EqValues {
    pub lambda:       [u64; 4],
    pub x3:           [u64; 4],
    pub y3:           [u64; 4],
    pub lambda_limbs: Vec<u128>,
    pub x3_limbs:     Vec<u128>,
    pub y3_limbs:     Vec<u128>,
    pub input_limbs:  Vec<Vec<u128>>,
}

/// Decompose EC result into u128 limbs, write lambda/x3/y3 to witness, and
/// return all decomposed values for `solve_and_write_equation`.
pub(super) fn setup_3eq_ec_hint(
    witness: &mut [Option<FieldElement>],
    output_start: usize,
    n: usize,
    limb_bits: u32,
    input_vals: &[[u64; 4]],
    ec_result: ([u64; 4], [u64; 4], [u64; 4]),
) -> EcHint3EqValues {
    let (lambda, x3, y3) = ec_result;
    let lambda_limbs = decompose_to_u128_limbs(&lambda, n, limb_bits);
    let x3_limbs = decompose_to_u128_limbs(&x3, n, limb_bits);
    let y3_limbs = decompose_to_u128_limbs(&y3, n, limb_bits);

    write_limbs(witness, output_start, &lambda_limbs);
    write_limbs(witness, output_start + n, &x3_limbs);
    write_limbs(witness, output_start + 2 * n, &y3_limbs);

    let input_limbs = input_vals
        .iter()
        .map(|v| decompose_to_u128_limbs(v, n, limb_bits))
        .collect();

    EcHint3EqValues {
        lambda,
        x3,
        y3,
        lambda_limbs,
        x3_limbs,
        y3_limbs,
        input_limbs,
    }
}
