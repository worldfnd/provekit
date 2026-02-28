/// BigInteger modular arithmetic on [u64; 4] limbs (256-bit).
///
/// These helpers compute modular inverse via Fermat's little theorem:
/// a^{-1} = a^{m-2} mod m, using schoolbook multiplication and
/// square-and-multiply exponentiation.

/// Schoolbook multiplication: 4×4 limbs → 8 limbs (256-bit × 256-bit →
/// 512-bit).
pub fn widening_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut result = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let product = (a[i] as u128) * (b[j] as u128) + (result[i + j] as u128) + carry;
            result[i + j] = product as u64;
            carry = product >> 64;
        }
        result[i + 4] = carry as u64;
    }
    result
}

/// Compare 8-limb value with 4-limb value (zero-extended to 8 limbs).
/// Returns Ordering::Greater if wide > narrow, etc.
#[cfg(test)]
fn cmp_wide_narrow(wide: &[u64; 8], narrow: &[u64; 4]) -> std::cmp::Ordering {
    // Check high limbs of wide (must all be zero for equality/less)
    for i in (4..8).rev() {
        if wide[i] != 0 {
            return std::cmp::Ordering::Greater;
        }
    }
    // Compare the low 4 limbs
    for i in (0..4).rev() {
        match wide[i].cmp(&narrow[i]) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Modular reduction of a 512-bit value by a 256-bit modulus.
/// Uses bit-by-bit long division.
fn reduce_wide(wide: &[u64; 8], modulus: &[u64; 4]) -> [u64; 4] {
    // Find the highest set bit in wide
    let mut highest_bit = 0;
    for i in (0..8).rev() {
        if wide[i] != 0 {
            highest_bit = i * 64 + (64 - wide[i].leading_zeros() as usize);
            break;
        }
    }
    if highest_bit == 0 {
        return [0u64; 4];
    }

    // Bit-by-bit long division
    // remainder starts at 0, we shift in bits from the dividend
    let mut remainder = [0u64; 4];
    for bit_pos in (0..highest_bit).rev() {
        // Left-shift remainder by 1
        let carry = shift_left_one(&mut remainder);
        debug_assert_eq!(carry, 0, "remainder overflow during shift");

        // Bring in the next bit from wide
        let limb_idx = bit_pos / 64;
        let bit_idx = bit_pos % 64;
        let bit = (wide[limb_idx] >> bit_idx) & 1;
        remainder[0] |= bit;

        // If remainder >= modulus, subtract
        if cmp_4limb(&remainder, modulus) != std::cmp::Ordering::Less {
            sub_4limb_inplace(&mut remainder, modulus);
        }
    }

    remainder
}

/// Left-shift a 4-limb number by 1 bit. Returns the carry-out bit.
fn shift_left_one(a: &mut [u64; 4]) -> u64 {
    let mut carry = 0u64;
    for limb in a.iter_mut() {
        let new_carry = *limb >> 63;
        *limb = (*limb << 1) | carry;
        carry = new_carry;
    }
    carry
}

/// Compare two 4-limb numbers.
pub fn cmp_4limb(a: &[u64; 4], b: &[u64; 4]) -> std::cmp::Ordering {
    for i in (0..4).rev() {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Subtract b from a in-place (a -= b). Assumes a >= b.
fn sub_4limb_inplace(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (diff, borrow1) = a[i].overflowing_sub(b[i]);
        let (diff2, borrow2) = diff.overflowing_sub(borrow);
        a[i] = diff2;
        borrow = (borrow1 as u64) + (borrow2 as u64);
    }
    debug_assert_eq!(borrow, 0, "subtraction underflow: a < b");
}

/// Modular multiplication: (a * b) mod m.
pub fn mul_mod(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
    let wide = widening_mul(a, b);
    reduce_wide(&wide, m)
}

/// Modular exponentiation: base^exp mod m using square-and-multiply.
pub fn mod_pow(base: &[u64; 4], exp: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
    // Find highest set bit in exp
    let mut highest_bit = 0;
    for i in (0..4).rev() {
        if exp[i] != 0 {
            highest_bit = i * 64 + (64 - exp[i].leading_zeros() as usize);
            break;
        }
    }
    if highest_bit == 0 {
        // exp == 0 → result = 1 (for m > 1)
        return [1, 0, 0, 0];
    }

    let mut result = [1u64, 0, 0, 0]; // 1
    for bit_pos in (0..highest_bit).rev() {
        // Square
        result = mul_mod(&result, &result, m);
        // Multiply if bit is set
        let limb_idx = bit_pos / 64;
        let bit_idx = bit_pos % 64;
        if (exp[limb_idx] >> bit_idx) & 1 == 1 {
            result = mul_mod(&result, base, m);
        }
    }

    result
}

/// Integer division with remainder: dividend = quotient * divisor + remainder,
/// where 0 <= remainder < divisor. Uses bit-by-bit long division.
pub fn divmod(dividend: &[u64; 4], divisor: &[u64; 4]) -> ([u64; 4], [u64; 4]) {
    // Find the highest set bit in dividend
    let mut highest_bit = 0;
    for i in (0..4).rev() {
        if dividend[i] != 0 {
            highest_bit = i * 64 + (64 - dividend[i].leading_zeros() as usize);
            break;
        }
    }
    if highest_bit == 0 {
        return ([0u64; 4], [0u64; 4]);
    }

    let mut quotient = [0u64; 4];
    let mut remainder = [0u64; 4];

    for bit_pos in (0..highest_bit).rev() {
        // Left-shift remainder by 1
        let carry = shift_left_one(&mut remainder);
        debug_assert_eq!(carry, 0, "remainder overflow during shift");

        // Bring in the next bit from dividend
        let limb_idx = bit_pos / 64;
        let bit_idx = bit_pos % 64;
        remainder[0] |= (dividend[limb_idx] >> bit_idx) & 1;

        // If remainder >= divisor, subtract and set quotient bit
        if cmp_4limb(&remainder, divisor) != std::cmp::Ordering::Less {
            sub_4limb_inplace(&mut remainder, divisor);
            quotient[limb_idx] |= 1u64 << bit_idx;
        }
    }

    (quotient, remainder)
}

/// Subtract a small u64 value from a 4-limb number. Assumes a >= small.
pub fn sub_u64(a: &[u64; 4], small: u64) -> [u64; 4] {
    let mut result = *a;
    let (diff, borrow) = result[0].overflowing_sub(small);
    result[0] = diff;
    if borrow {
        for limb in result[1..].iter_mut() {
            let (d, b) = limb.overflowing_sub(1);
            *limb = d;
            if !b {
                break;
            }
        }
    }
    result
}

/// Add two 4-limb (256-bit) numbers, returning a 5-limb result with carry.
pub fn add_4limb(a: &[u64; 4], b: &[u64; 4]) -> [u64; 5] {
    let mut result = [0u64; 5];
    let mut carry = 0u64;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        result[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
    }
    result[4] = carry;
    result
}

/// Offset added to signed carries to make them non-negative for range checking.
/// Carries are bounded by |c| < 2^88, so adding 2^88 ensures c_unsigned >= 0.
pub const CARRY_OFFSET: u128 = 1u128 << 88;

/// Integer division of a 512-bit dividend by a 256-bit divisor.
/// Returns (quotient, remainder) where both fit in 256 bits.
/// Panics if the quotient would exceed 256 bits.
pub fn divmod_wide(dividend: &[u64; 8], divisor: &[u64; 4]) -> ([u64; 4], [u64; 4]) {
    let mut highest_bit = 0;
    for i in (0..8).rev() {
        if dividend[i] != 0 {
            highest_bit = i * 64 + (64 - dividend[i].leading_zeros() as usize);
            break;
        }
    }
    if highest_bit == 0 {
        return ([0u64; 4], [0u64; 4]);
    }

    let mut quotient = [0u64; 4];
    let mut remainder = [0u64; 4];

    for bit_pos in (0..highest_bit).rev() {
        let shift_carry = shift_left_one(&mut remainder);

        let limb_idx = bit_pos / 64;
        let bit_idx = bit_pos % 64;
        remainder[0] |= (dividend[limb_idx] >> bit_idx) & 1;

        // If shift_carry is set, the effective remainder is 2^256 + remainder,
        // which is always > any 256-bit divisor, so we must subtract.
        if shift_carry != 0 || cmp_4limb(&remainder, divisor) != std::cmp::Ordering::Less {
            // Subtract divisor with inline borrow tracking (handles the case
            // where remainder < divisor but shift_carry provides the extra bit).
            let mut borrow = 0u64;
            for i in 0..4 {
                let (d1, b1) = remainder[i].overflowing_sub(divisor[i]);
                let (d2, b2) = d1.overflowing_sub(borrow);
                remainder[i] = d2;
                borrow = (b1 as u64) + (b2 as u64);
            }
            // When shift_carry was set, the borrow absorbs it (they cancel out).
            debug_assert_eq!(
                borrow, shift_carry,
                "unexpected borrow in divmod_wide at bit_pos {}",
                bit_pos
            );

            assert!(bit_pos < 256, "quotient exceeds 256 bits");
            quotient[bit_pos / 64] |= 1u64 << (bit_pos % 64);
        }
    }

    (quotient, remainder)
}

/// Split a 256-bit value into two 128-bit halves: (lo, hi).
pub fn decompose_128(val: &[u64; 4]) -> (u128, u128) {
    let lo = val[0] as u128 | ((val[1] as u128) << 64);
    let hi = val[2] as u128 | ((val[3] as u128) << 64);
    (lo, hi)
}

/// Split a 256-bit value into three 86-bit limbs: (l0, l1, l2).
/// l0 = bits [0..86), l1 = bits [86..172), l2 = bits [172..256).
pub fn decompose_86(val: &[u64; 4]) -> (u128, u128, u128) {
    let mask_86: u128 = (1u128 << 86) - 1;
    let lo128 = val[0] as u128 | ((val[1] as u128) << 64);
    let hi128 = val[2] as u128 | ((val[3] as u128) << 64);

    let l0 = lo128 & mask_86;
    // l1 spans bits [86..172): 42 bits from lo128, 44 bits from hi128
    let l1 = ((lo128 >> 86) | (hi128 << 42)) & mask_86;
    // l2 = bits [172..256): 84 bits from hi128
    let l2 = hi128 >> 44;

    (l0, l1, l2)
}

/// Compute carry values c0..c3 from the 86-bit schoolbook column equations
/// for the identity a*b = p*q + r (base W = 2^86).
///
/// Column equations:
///   col0: a0*b0 - p0*q0 - r0 = c0*W
///   col1: a0*b1 + a1*b0 - p0*q1 - p1*q0 - r1 + c0 = c1*W
///   col2: a0*b2 + a1*b1 + a2*b0 - p0*q2 - p1*q1 - p2*q0 - r2 + c1 = c2*W
///   col3: a1*b2 + a2*b1 - p1*q2 - p2*q1 + c2 = c3*W
///   col4: a2*b2 - p2*q2 + c3 = 0
pub fn compute_carries_86(
    a: [u128; 3],
    b: [u128; 3],
    p: [u128; 3],
    q: [u128; 3],
    r: [u128; 3],
) -> [i128; 4] {
    // Helper: convert u128 to [u64; 4]
    fn to4(v: u128) -> [u64; 4] {
        [v as u64, (v >> 64) as u64, 0, 0]
    }

    // Helper: multiply two 86-bit values → [u64; 4] (result < 2^172)
    fn mul86(x: u128, y: u128) -> [u64; 4] {
        let w = widening_mul(&to4(x), &to4(y));
        [w[0], w[1], w[2], w[3]]
    }

    // Helper: add two [u64; 4] values
    fn add4(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let mut r = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let s = a[i] as u128 + b[i] as u128 + carry;
            r[i] = s as u64;
            carry = s >> 64;
        }
        r
    }

    // Helper: subtract two [u64; 4] values (assumes a >= b)
    fn sub4(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let mut r = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d1, b1) = a[i].overflowing_sub(b[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            r[i] = d2;
            borrow = b1 as u64 + b2 as u64;
        }
        r
    }

    // Helper: right-shift [u64; 4] by 86 bits (= 64 + 22)
    fn shr86(a: [u64; 4]) -> [u64; 4] {
        let s = [a[1], a[2], a[3], 0u64];
        [
            (s[0] >> 22) | (s[1] << 42),
            (s[1] >> 22) | (s[2] << 42),
            s[2] >> 22,
            0,
        ]
    }

    // Positive column sums (a_i * b_j terms)
    let pos = [
        mul86(a[0], b[0]),
        add4(mul86(a[0], b[1]), mul86(a[1], b[0])),
        add4(
            add4(mul86(a[0], b[2]), mul86(a[1], b[1])),
            mul86(a[2], b[0]),
        ),
        add4(mul86(a[1], b[2]), mul86(a[2], b[1])),
        mul86(a[2], b[2]),
    ];

    // Negative column sums (p_i * q_j + r_i terms)
    let neg = [
        add4(mul86(p[0], q[0]), to4(r[0])),
        add4(add4(mul86(p[0], q[1]), mul86(p[1], q[0])), to4(r[1])),
        add4(
            add4(
                add4(mul86(p[0], q[2]), mul86(p[1], q[1])),
                mul86(p[2], q[0]),
            ),
            to4(r[2]),
        ),
        add4(mul86(p[1], q[2]), mul86(p[2], q[1])),
        mul86(p[2], q[2]),
    ];

    let mut carries = [0i128; 4];
    let mut carry_pos = [0u64; 4];
    let mut carry_neg = [0u64; 4];

    for col in 0..4 {
        let total_pos = add4(pos[col], carry_pos);
        let total_neg = add4(neg[col], carry_neg);

        let (is_neg, diff) = if cmp_4limb(&total_pos, &total_neg) != std::cmp::Ordering::Less {
            (false, sub4(total_pos, total_neg))
        } else {
            (true, sub4(total_neg, total_pos))
        };

        // Lower 86 bits must be zero (divisibility check)
        let mask_86 = (1u128 << 86) - 1;
        let low86 = (diff[0] as u128 | ((diff[1] as u128) << 64)) & mask_86;
        debug_assert_eq!(low86, 0, "column {} not divisible by W=2^86", col);

        let carry_mag = shr86(diff);
        debug_assert_eq!(carry_mag[2], 0, "carry overflow in column {}", col);
        debug_assert_eq!(carry_mag[3], 0, "carry overflow in column {}", col);

        let carry_val = carry_mag[0] as i128 | ((carry_mag[1] as i128) << 64);
        carries[col] = if is_neg { -carry_val } else { carry_val };

        if is_neg {
            carry_pos = [0; 4];
            carry_neg = carry_mag;
        } else {
            carry_pos = carry_mag;
            carry_neg = [0; 4];
        }
    }

    // Verify column 4 balances
    let final_pos = add4(pos[4], carry_pos);
    let final_neg = add4(neg[4], carry_neg);
    debug_assert_eq!(
        final_pos, final_neg,
        "column 4 should balance: a2*b2 - p2*q2 + c3 = 0"
    );

    carries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_widening_mul_small() {
        // 3 * 7 = 21
        let a = [3, 0, 0, 0];
        let b = [7, 0, 0, 0];
        let result = widening_mul(&a, &b);
        assert_eq!(result[0], 21);
        assert_eq!(result[1..], [0; 7]);
    }

    #[test]
    fn test_widening_mul_overflow() {
        // u64::MAX * u64::MAX = (2^64-1)^2 = 2^128 - 2^65 + 1
        let a = [u64::MAX, 0, 0, 0];
        let b = [u64::MAX, 0, 0, 0];
        let result = widening_mul(&a, &b);
        // (2^64-1)^2 = 0xFFFFFFFFFFFFFFFE_0000000000000001
        assert_eq!(result[0], 1);
        assert_eq!(result[1], u64::MAX - 1);
        assert_eq!(result[2..], [0; 6]);
    }

    #[test]
    fn test_reduce_wide_no_reduction() {
        // 5 mod 7 = 5
        let wide = [5, 0, 0, 0, 0, 0, 0, 0];
        let modulus = [7, 0, 0, 0];
        assert_eq!(reduce_wide(&wide, &modulus), [5, 0, 0, 0]);
    }

    #[test]
    fn test_reduce_wide_basic() {
        // 10 mod 7 = 3
        let wide = [10, 0, 0, 0, 0, 0, 0, 0];
        let modulus = [7, 0, 0, 0];
        assert_eq!(reduce_wide(&wide, &modulus), [3, 0, 0, 0]);
    }

    #[test]
    fn test_mul_mod_small() {
        // (5 * 3) mod 7 = 15 mod 7 = 1
        let a = [5, 0, 0, 0];
        let b = [3, 0, 0, 0];
        let m = [7, 0, 0, 0];
        assert_eq!(mul_mod(&a, &b, &m), [1, 0, 0, 0]);
    }

    #[test]
    fn test_mod_pow_small() {
        // 3^4 mod 7 = 81 mod 7 = 4
        let base = [3, 0, 0, 0];
        let exp = [4, 0, 0, 0];
        let m = [7, 0, 0, 0];
        assert_eq!(mod_pow(&base, &exp, &m), [4, 0, 0, 0]);
    }

    #[test]
    fn test_fermat_inverse_small() {
        // Inverse of 3 mod 7: 3^{7-2} = 3^5 mod 7 = 243 mod 7 = 5
        // Check: 3 * 5 = 15 = 2*7 + 1 ≡ 1 (mod 7) ✓
        let a = [3, 0, 0, 0];
        let m = [7, 0, 0, 0];
        let exp = sub_u64(&m, 2); // m - 2 = 5
        let inv = mod_pow(&a, &exp, &m);
        assert_eq!(inv, [5, 0, 0, 0]);
        // Verify: a * inv mod m = 1
        assert_eq!(mul_mod(&a, &inv, &m), [1, 0, 0, 0]);
    }

    #[test]
    fn test_fermat_inverse_prime_23() {
        // Inverse of 5 mod 23: 5^{21} mod 23
        // 5^{-1} mod 23 = 14 (because 5*14 = 70 = 3*23 + 1)
        let a = [5, 0, 0, 0];
        let m = [23, 0, 0, 0];
        let exp = sub_u64(&m, 2);
        let inv = mod_pow(&a, &exp, &m);
        assert_eq!(inv, [14, 0, 0, 0]);
        assert_eq!(mul_mod(&a, &inv, &m), [1, 0, 0, 0]);
    }

    #[test]
    fn test_sub_u64_basic() {
        assert_eq!(sub_u64(&[10, 0, 0, 0], 3), [7, 0, 0, 0]);
    }

    #[test]
    fn test_sub_u64_borrow() {
        // [0, 1, 0, 0] = 2^64; subtract 1 → [u64::MAX, 0, 0, 0]
        assert_eq!(sub_u64(&[0, 1, 0, 0], 1), [u64::MAX, 0, 0, 0]);
    }

    #[test]
    fn test_fermat_inverse_large_prime() {
        // Use a 128-bit prime: p = 2^127 - 1 = 170141183460469231731687303715884105727
        // In limbs: [u64::MAX, 2^63 - 1, 0, 0]
        let p = [u64::MAX, (1u64 << 63) - 1, 0, 0];

        // a = 42
        let a = [42, 0, 0, 0];
        let exp = sub_u64(&p, 2);
        let inv = mod_pow(&a, &exp, &p);

        // Verify: a * inv mod p = 1
        assert_eq!(mul_mod(&a, &inv, &p), [1, 0, 0, 0]);
    }

    #[test]
    fn test_cmp_wide_narrow() {
        let wide = [5, 0, 0, 0, 0, 0, 0, 0];
        let narrow = [5, 0, 0, 0];
        assert_eq!(cmp_wide_narrow(&wide, &narrow), std::cmp::Ordering::Equal);

        let wide_greater = [0, 0, 0, 0, 1, 0, 0, 0];
        assert_eq!(
            cmp_wide_narrow(&wide_greater, &narrow),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_mod_pow_zero_exp() {
        // a^0 mod m = 1
        let base = [42, 0, 0, 0];
        let exp = [0, 0, 0, 0];
        let m = [7, 0, 0, 0];
        assert_eq!(mod_pow(&base, &exp, &m), [1, 0, 0, 0]);
    }

    #[test]
    fn test_mod_pow_one_exp() {
        // a^1 mod m = a mod m
        let base = [10, 0, 0, 0];
        let exp = [1, 0, 0, 0];
        let m = [7, 0, 0, 0];
        assert_eq!(mod_pow(&base, &exp, &m), [3, 0, 0, 0]);
    }

    #[test]
    fn test_divmod_exact() {
        // 21 / 7 = 3 remainder 0
        let (q, r) = divmod(&[21, 0, 0, 0], &[7, 0, 0, 0]);
        assert_eq!(q, [3, 0, 0, 0]);
        assert_eq!(r, [0, 0, 0, 0]);
    }

    #[test]
    fn test_divmod_with_remainder() {
        // 17 / 7 = 2 remainder 3
        let (q, r) = divmod(&[17, 0, 0, 0], &[7, 0, 0, 0]);
        assert_eq!(q, [2, 0, 0, 0]);
        assert_eq!(r, [3, 0, 0, 0]);
    }

    #[test]
    fn test_divmod_smaller_dividend() {
        // 5 / 7 = 0 remainder 5
        let (q, r) = divmod(&[5, 0, 0, 0], &[7, 0, 0, 0]);
        assert_eq!(q, [0, 0, 0, 0]);
        assert_eq!(r, [5, 0, 0, 0]);
    }

    #[test]
    fn test_divmod_zero_dividend() {
        let (q, r) = divmod(&[0, 0, 0, 0], &[7, 0, 0, 0]);
        assert_eq!(q, [0, 0, 0, 0]);
        assert_eq!(r, [0, 0, 0, 0]);
    }

    #[test]
    fn test_divmod_large() {
        // 2^64 / 3 = 6148914691236517205 remainder 1
        // 2^64 in limbs: [0, 1, 0, 0]
        let (q, r) = divmod(&[0, 1, 0, 0], &[3, 0, 0, 0]);
        assert_eq!(q, [6148914691236517205, 0, 0, 0]);
        assert_eq!(r, [1, 0, 0, 0]);
        // Verify: q * 3 + 1 = 2^64
        assert_eq!(6148914691236517205u64.wrapping_mul(3).wrapping_add(1), 0u64);
        // wraps to 0 in u64 = 2^64
    }

    #[test]
    fn test_divmod_consistency() {
        // Verify dividend = quotient * divisor + remainder for various inputs
        let cases: Vec<([u64; 4], [u64; 4])> = vec![
            ([100, 0, 0, 0], [7, 0, 0, 0]),
            ([u64::MAX, 0, 0, 0], [1000, 0, 0, 0]),
            ([0, 1, 0, 0], [u64::MAX, 0, 0, 0]), // 2^64 / (2^64 - 1)
        ];
        for (dividend, divisor) in cases {
            let (q, r) = divmod(&dividend, &divisor);
            // Verify: q * divisor + r = dividend
            let product = widening_mul(&q, &divisor);
            // Add remainder to product
            let mut sum = product;
            let mut carry = 0u128;
            for i in 0..4 {
                let s = (sum[i] as u128) + (r[i] as u128) + carry;
                sum[i] = s as u64;
                carry = s >> 64;
            }
            for i in 4..8 {
                let s = (sum[i] as u128) + carry;
                sum[i] = s as u64;
                carry = s >> 64;
            }
            // sum should equal dividend (zero-extended to 8 limbs)
            let mut expected = [0u64; 8];
            expected[..4].copy_from_slice(&dividend);
            assert_eq!(sum, expected, "dividend={dividend:?} divisor={divisor:?}");
        }
    }

    #[test]
    fn test_divmod_wide_small() {
        // 21 / 7 = 3 remainder 0 (512-bit dividend)
        let dividend = [21, 0, 0, 0, 0, 0, 0, 0];
        let divisor = [7, 0, 0, 0];
        let (q, r) = divmod_wide(&dividend, &divisor);
        assert_eq!(q, [3, 0, 0, 0]);
        assert_eq!(r, [0, 0, 0, 0]);
    }

    #[test]
    fn test_divmod_wide_large() {
        // Compute a * b where a, b are 256-bit, then divide by a
        // Should give quotient = b, remainder = 0
        let a = [0xffffffffffffffff, 0xffffffff, 0x0, 0xffffffff00000001]; // secp256r1 p
        let b = [42, 0, 0, 0];
        let product = widening_mul(&a, &b);
        let (q, r) = divmod_wide(&product, &a);
        assert_eq!(q, b);
        assert_eq!(r, [0, 0, 0, 0]);
    }

    #[test]
    fn test_divmod_wide_with_remainder() {
        // (a * b + 5) / a = b remainder 5
        let a = [0xffffffffffffffff, 0xffffffff, 0x0, 0xffffffff00000001];
        let b = [100, 0, 0, 0];
        let mut product = widening_mul(&a, &b);
        // Add 5
        let (sum, overflow) = product[0].overflowing_add(5);
        product[0] = sum;
        if overflow {
            for i in 1..8 {
                let (s, o) = product[i].overflowing_add(1);
                product[i] = s;
                if !o {
                    break;
                }
            }
        }
        let (q, r) = divmod_wide(&product, &a);
        assert_eq!(q, b);
        assert_eq!(r, [5, 0, 0, 0]);
    }

    #[test]
    fn test_divmod_wide_consistency() {
        // Verify: q * divisor + r = dividend
        let a = [
            0x123456789abcdef0,
            0xfedcba9876543210,
            0x1111111111111111,
            0x2222222222222222,
        ];
        let b = [0xaabbccdd, 0x11223344, 0x55667788, 0x99001122];
        let product = widening_mul(&a, &b);
        let divisor = [0xffffffffffffffff, 0xffffffff, 0x0, 0xffffffff00000001];
        let (q, r) = divmod_wide(&product, &divisor);

        // Verify: q * divisor + r = product
        let qd = widening_mul(&q, &divisor);
        let mut sum = qd;
        let mut carry = 0u128;
        for i in 0..4 {
            let s = (sum[i] as u128) + (r[i] as u128) + carry;
            sum[i] = s as u64;
            carry = s >> 64;
        }
        for i in 4..8 {
            let s = (sum[i] as u128) + carry;
            sum[i] = s as u64;
            carry = s >> 64;
        }
        assert_eq!(sum, product);
    }

    #[test]
    fn test_decompose_128_roundtrip() {
        let val = [
            0x123456789abcdef0,
            0xfedcba9876543210,
            0x1111111111111111,
            0x2222222222222222,
        ];
        let (lo, hi) = decompose_128(&val);
        // Roundtrip
        assert_eq!(lo as u64, val[0]);
        assert_eq!((lo >> 64) as u64, val[1]);
        assert_eq!(hi as u64, val[2]);
        assert_eq!((hi >> 64) as u64, val[3]);
    }

    #[test]
    fn test_decompose_86_roundtrip() {
        let val = [
            0x123456789abcdef0,
            0xfedcba9876543210,
            0x1111111111111111,
            0x2222222222222222,
        ];
        let (l0, l1, l2) = decompose_86(&val);

        // Each limb should be < 2^86
        assert!(l0 < (1u128 << 86));
        assert!(l1 < (1u128 << 86));
        // l2 has at most 84 bits (256 - 172)
        assert!(l2 < (1u128 << 84));

        // Roundtrip: l0 + l1 * 2^86 + l2 * 2^172 should equal val
        // Build from limbs back to [u64; 4]
        let mut reconstructed = [0u128; 2]; // lo128, hi128
        reconstructed[0] = l0;
        // l1 starts at bit 86
        reconstructed[0] |= (l1 & ((1u128 << 42) - 1)) << 86; // lower 42 bits of l1 into lo128
        reconstructed[1] = l1 >> 42; // upper 44 bits of l1
                                     // l2 starts at bit 172 = 128 + 44
        reconstructed[1] |= l2 << 44;

        assert_eq!(reconstructed[0] as u64, val[0]);
        assert_eq!((reconstructed[0] >> 64) as u64, val[1]);
        assert_eq!(reconstructed[1] as u64, val[2]);
        assert_eq!((reconstructed[1] >> 64) as u64, val[3]);
    }

    #[test]
    fn test_decompose_86_secp256r1_p() {
        // secp256r1 field modulus
        let p = [0xffffffffffffffff, 0xffffffff, 0x0, 0xffffffff00000001];
        let (l0, l1, l2) = decompose_86(&p);
        assert!(l0 < (1u128 << 86));
        assert!(l1 < (1u128 << 86));
        assert!(l2 < (1u128 << 84));
    }

    #[test]
    fn test_compute_carries_86_simple() {
        // Test with small values: a=3, b=5, p=7
        // a*b = 15, 15 / 7 = 2 remainder 1
        // So q=2, r=1
        let a_val = [3u64, 0, 0, 0];
        let b_val = [5, 0, 0, 0];
        let p_val = [7, 0, 0, 0];
        let product = widening_mul(&a_val, &b_val);
        let (q_val, r_val) = divmod_wide(&product, &p_val);
        assert_eq!(q_val, [2, 0, 0, 0]);
        assert_eq!(r_val, [1, 0, 0, 0]);

        let (a0, a1, a2) = decompose_86(&a_val);
        let (b0, b1, b2) = decompose_86(&b_val);
        let (p0, p1, p2) = decompose_86(&p_val);
        let (q0, q1, q2) = decompose_86(&q_val);
        let (r0, r1, r2) = decompose_86(&r_val);

        let carries = compute_carries_86([a0, a1, a2], [b0, b1, b2], [p0, p1, p2], [q0, q1, q2], [
            r0, r1, r2,
        ]);
        // For small values, all carries should be 0
        assert_eq!(carries, [0, 0, 0, 0]);
    }

    #[test]
    fn test_compute_carries_86_secp256r1() {
        // Test with secp256r1-sized values
        let p = [0xffffffffffffffff, 0xffffffff, 0x0, 0xffffffff00000001];
        let a_val = [0x123456789abcdef0, 0xfedcba9876543210, 0x0, 0x0]; // < p
        let b_val = [0xaabbccddeeff0011, 0x1122334455667788, 0x0, 0x0]; // < p

        let product = widening_mul(&a_val, &b_val);
        let (q_val, r_val) = divmod_wide(&product, &p);

        // Verify a*b = p*q + r
        let pq = widening_mul(&p, &q_val);
        let mut sum = pq;
        let mut carry = 0u128;
        for i in 0..4 {
            let s = sum[i] as u128 + r_val[i] as u128 + carry;
            sum[i] = s as u64;
            carry = s >> 64;
        }
        for i in 4..8 {
            let s = sum[i] as u128 + carry;
            sum[i] = s as u64;
            carry = s >> 64;
        }
        assert_eq!(sum, product);

        // Compute 86-bit decompositions
        let (a0, a1, a2) = decompose_86(&a_val);
        let (b0, b1, b2) = decompose_86(&b_val);
        let (p0, p1, p2) = decompose_86(&p);
        let (q0, q1, q2) = decompose_86(&q_val);
        let (r0, r1, r2) = decompose_86(&r_val);

        // This should not panic
        let _carries =
            compute_carries_86([a0, a1, a2], [b0, b1, b2], [p0, p1, p2], [q0, q1, q2], [
                r0, r1, r2,
            ]);
    }
}
