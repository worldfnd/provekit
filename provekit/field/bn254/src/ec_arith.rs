//! EC point arithmetic on [u64; 4] (256-bit affine coordinates).
//!
//! These functions are used by the prover's witness builders to compute
//! EC hints (doubling, addition, scalar multiplication) and verification
//! carries for schoolbook column equations.

use provekit_common::u256_arith::{mod_add, mod_inv as mod_inverse, mod_mul as mul_mod, mod_sub};

/// EC point doubling with lambda exposed: returns (lambda, x3, y3).
///
/// Used by the `EcDoubleHint` prover which needs lambda as a witness.
pub fn ec_point_double_with_lambda(
    px: &[u64; 4],
    py: &[u64; 4],
    a: &[u64; 4],
    p: &[u64; 4],
) -> ([u64; 4], [u64; 4], [u64; 4]) {
    let x_sq = mul_mod(px, px, p);
    let two_x_sq = mod_add(&x_sq, &x_sq, p);
    let three_x_sq = mod_add(&two_x_sq, &x_sq, p);
    let numerator = mod_add(&three_x_sq, a, p);
    let two_y = mod_add(py, py, p);
    let denom_inv = mod_inverse(&two_y, p);
    let lambda = mul_mod(&numerator, &denom_inv, p);

    let lambda_sq = mul_mod(&lambda, &lambda, p);
    let two_x = mod_add(px, px, p);
    let x3 = mod_sub(&lambda_sq, &two_x, p);

    let x_minus_x3 = mod_sub(px, &x3, p);
    let lambda_dx = mul_mod(&lambda, &x_minus_x3, p);
    let y3 = mod_sub(&lambda_dx, py, p);

    (lambda, x3, y3)
}

/// EC point doubling in affine coordinates on y^2 = x^3 + ax + b.
/// Returns (x3, y3) = 2*(px, py).
pub fn ec_point_double(
    px: &[u64; 4],
    py: &[u64; 4],
    a: &[u64; 4],
    p: &[u64; 4],
) -> ([u64; 4], [u64; 4]) {
    let (_, x3, y3) = ec_point_double_with_lambda(px, py, a, p);
    (x3, y3)
}

/// EC point addition with lambda exposed: returns (lambda, x3, y3).
///
/// Used by the `EcAddHint` prover which needs lambda as a witness.
pub fn ec_point_add_with_lambda(
    p1x: &[u64; 4],
    p1y: &[u64; 4],
    p2x: &[u64; 4],
    p2y: &[u64; 4],
    p: &[u64; 4],
) -> ([u64; 4], [u64; 4], [u64; 4]) {
    let numerator = mod_sub(p2y, p1y, p);
    let denominator = mod_sub(p2x, p1x, p);
    let denom_inv = mod_inverse(&denominator, p);
    let lambda = mul_mod(&numerator, &denom_inv, p);

    let lambda_sq = mul_mod(&lambda, &lambda, p);
    let x1_plus_x2 = mod_add(p1x, p2x, p);
    let x3 = mod_sub(&lambda_sq, &x1_plus_x2, p);

    let x1_minus_x3 = mod_sub(p1x, &x3, p);
    let lambda_dx = mul_mod(&lambda, &x1_minus_x3, p);
    let y3 = mod_sub(&lambda_dx, p1y, p);

    (lambda, x3, y3)
}

/// EC point addition in affine coordinates on y^2 = x^3 + ax + b.
/// Returns (x3, y3) = (p1x, p1y) + (p2x, p2y). Requires p1x != p2x.
pub fn ec_point_add(
    p1x: &[u64; 4],
    p1y: &[u64; 4],
    p2x: &[u64; 4],
    p2y: &[u64; 4],
    p: &[u64; 4],
) -> ([u64; 4], [u64; 4]) {
    let (_, x3, y3) = ec_point_add_with_lambda(p1x, p1y, p2x, p2y, p);
    (x3, y3)
}

/// EC scalar multiplication via double-and-add: returns \[scalar\]*P.
///
/// # Panics
/// Panics if `scalar` is zero (the point at infinity is not representable in
/// affine coordinates).
pub fn ec_scalar_mul(
    px: &[u64; 4],
    py: &[u64; 4],
    scalar: &[u64; 4],
    a: &[u64; 4],
    p: &[u64; 4],
) -> ([u64; 4], [u64; 4]) {
    // Find highest set bit in scalar
    let mut highest_bit = 0;
    for i in (0..4).rev() {
        if scalar[i] != 0 {
            highest_bit = i * 64 + (64 - scalar[i].leading_zeros() as usize);
            break;
        }
    }
    if highest_bit == 0 {
        // scalar == 0 → point at infinity (not representable in affine)
        panic!("ec_scalar_mul: scalar is zero");
    }

    // Start from the MSB-1 and double-and-add
    let mut rx = *px;
    let mut ry = *py;

    for bit_pos in (0..highest_bit - 1).rev() {
        // Double
        let (dx, dy) = ec_point_double(&rx, &ry, a, p);
        rx = dx;
        ry = dy;

        // Add if bit is set
        let limb_idx = bit_pos / 64;
        let bit_idx = bit_pos % 64;
        if (scalar[limb_idx] >> bit_idx) & 1 == 1 {
            let (ax, ay) = ec_point_add(&rx, &ry, px, py, p);
            rx = ax;
            ry = ay;
        }
    }

    (rx, ry)
}

/// Compute unsigned-offset carries for a general merged column equation.
///
/// Each `product_set` entry is (a_limbs, b_limbs, coefficient):
///   LHS_terms = Σ coeff * Σ_{i+j=k} a\[i\]*b\[j\]
///
/// Each `linear_set` entry is (limb_values, coefficient) for non-product terms:
///   LHS_terms += Σ coeff * val\[k\]  (for k < val.len())
///
/// The equation verified is:
///   LHS + Σ p\[i\]*q_neg\[j\] = RHS + Σ p\[i\]*q_pos\[j\] + carry_chain
///
/// `q_pos_limbs` and `q_neg_limbs` are both non-negative; at most one is
/// non-zero.
pub fn compute_ec_verification_carries(
    product_sets: &[(&[u128], &[u128], i64)],
    linear_terms: &[(Vec<i128>, i64)], // (limb_values extended to 2N-1, coefficient)
    p_limbs: &[u128],
    q_pos_limbs: &[u128],
    q_neg_limbs: &[u128],
    n: usize,
    limb_bits: u32,
    max_coeff_sum: u64,
) -> Vec<u128> {
    use {num_bigint::BigInt, provekit_common::u256_arith::ceil_log2};

    let w = limb_bits;
    let num_columns = 2 * n - 1;
    let num_carries = num_columns - 1;

    let extra_bits = ceil_log2(max_coeff_sum * n as u64) + 1;
    let carry_offset_bits = w + extra_bits;
    let carry_offset = BigInt::from(1u64) << carry_offset_bits;

    let mut carries = Vec::with_capacity(num_carries);
    let mut carry = BigInt::from(0);

    for k in 0..num_columns {
        let mut col_value = BigInt::from(0);

        // Product terms
        for &(a, b, coeff) in product_sets {
            for i in 0..n {
                let j = k as isize - i as isize;
                if j >= 0 && (j as usize) < n {
                    col_value +=
                        BigInt::from(coeff) * BigInt::from(a[i]) * BigInt::from(b[j as usize]);
                }
            }
        }

        // Linear terms
        for (vals, coeff) in linear_terms {
            if k < vals.len() {
                col_value += BigInt::from(*coeff) * BigInt::from(vals[k]);
            }
        }

        // p*q_neg on positive side, p*q_pos on negative side
        for i in 0..n {
            let j = k as isize - i as isize;
            if j >= 0 && (j as usize) < n {
                col_value += BigInt::from(p_limbs[i]) * BigInt::from(q_neg_limbs[j as usize]);
                col_value -= BigInt::from(p_limbs[i]) * BigInt::from(q_pos_limbs[j as usize]);
            }
        }

        col_value += &carry;

        if k < num_carries {
            let mask = (BigInt::from(1u64) << w) - 1;
            debug_assert_eq!(
                &col_value & &mask,
                BigInt::from(0),
                "non-zero remainder at column {k}: col_value={col_value}"
            );
            carry = &col_value >> w;
            let stored = &carry + &carry_offset;
            carries.push(bigint_to_u128(&stored));
        } else {
            debug_assert_eq!(
                col_value,
                BigInt::from(0),
                "non-zero final column value: {col_value}"
            );
        }
    }

    carries
}

/// Convert a non-negative `BigInt` to `u128`. Panics if negative or too large.
fn bigint_to_u128(v: &num_bigint::BigInt) -> u128 {
    use num_bigint::Sign;
    assert!(v.sign() != Sign::Minus, "bigint_to_u128: negative value");
    let (_, bytes) = v.to_bytes_le();
    assert!(bytes.len() <= 16, "bigint_to_u128: value exceeds 128 bits");
    let mut buf = [0u8; 16];
    buf[..bytes.len()].copy_from_slice(&bytes);
    u128::from_le_bytes(buf)
}
