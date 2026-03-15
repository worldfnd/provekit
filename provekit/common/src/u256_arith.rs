//! 256-bit unsigned integer modular arithmetic.
//!
//! Shared across r1cs-compiler (compile-time EC point precomputation) and
//! prover (witness solving). Pure `[u64; 4]` arithmetic with no external
//! dependencies.

/// 256-bit unsigned integer as 4 little-endian u64 limbs.
pub type U256 = [u64; 4];

/// Returns true if a >= b.
pub fn gte(a: &U256, b: &U256) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true // equal
}

/// a + b, returns (result, carry).
pub fn add(a: &U256, b: &U256) -> (U256, bool) {
    let mut result = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        carry += a[i] as u128 + b[i] as u128;
        result[i] = carry as u64;
        carry >>= 64;
    }
    (result, carry != 0)
}

/// a - b, returns (result, borrow).
pub fn sub(a: &U256, b: &U256) -> (U256, bool) {
    let mut result = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow as u64);
        result[i] = d2;
        borrow = b1 || b2;
    }
    (result, borrow)
}

/// (a + b) mod p.
pub fn mod_add(a: &U256, b: &U256, p: &U256) -> U256 {
    let (s, overflow) = add(a, b);
    if overflow || gte(&s, p) {
        sub(&s, p).0
    } else {
        s
    }
}

/// (a - b) mod p.
pub fn mod_sub(a: &U256, b: &U256, p: &U256) -> U256 {
    let (d, borrow) = sub(a, b);
    if borrow {
        add(&d, p).0
    } else {
        d
    }
}

/// Schoolbook multiplication: 4×4 limbs → 8 limbs (256-bit × 256-bit →
/// 512-bit).
pub fn widening_mul(a: &U256, b: &U256) -> [u64; 8] {
    let mut result = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let prod = (a[i] as u128) * (b[j] as u128) + result[i + j] as u128 + carry;
            result[i + j] = prod as u64;
            carry = prod >> 64;
        }
        result[i + 4] = result[i + 4].wrapping_add(carry as u64);
    }
    result
}

/// Reduce a 512-bit value mod a 256-bit prime using bit-by-bit long division.
pub fn reduce_wide(wide: &[u64; 8], p: &U256) -> U256 {
    let mut total_bits = 0;
    for i in (0..8).rev() {
        if wide[i] != 0 {
            total_bits = i * 64 + (64 - wide[i].leading_zeros() as usize);
            break;
        }
    }
    if total_bits == 0 {
        return [0; 4];
    }

    let mut r = [0u64; 4];
    for bit_idx in (0..total_bits).rev() {
        // Left shift r by 1
        let overflow = r[3] >> 63;
        for j in (1..4).rev() {
            r[j] = (r[j] << 1) | (r[j - 1] >> 63);
        }
        r[0] <<= 1;

        // Insert current bit
        let word = bit_idx / 64;
        let bit = bit_idx % 64;
        r[0] |= (wide[word] >> bit) & 1;

        // If r >= p (or overflow from shift), subtract p
        if overflow != 0 || gte(&r, p) {
            r = sub(&r, p).0;
        }
    }
    r
}

/// (a * b) mod p.
pub fn mod_mul(a: &U256, b: &U256, p: &U256) -> U256 {
    let wide = widening_mul(a, b);
    reduce_wide(&wide, p)
}

/// a^exp mod p using square-and-multiply.
pub fn mod_pow(base: &U256, exp: &U256, p: &U256) -> U256 {
    let mut highest_bit = 0;
    for i in (0..4).rev() {
        if exp[i] != 0 {
            highest_bit = i * 64 + (64 - exp[i].leading_zeros() as usize);
            break;
        }
    }
    if highest_bit == 0 {
        return [1, 0, 0, 0];
    }

    let mut result: U256 = [1, 0, 0, 0];
    let mut base = *base;
    for bit_idx in 0..highest_bit {
        let word = bit_idx / 64;
        let bit = bit_idx % 64;
        if (exp[word] >> bit) & 1 == 1 {
            result = mod_mul(&result, &base, p);
        }
        base = mod_mul(&base, &base, p);
    }
    result
}

/// a^(-1) mod p via Fermat's little theorem: a^(p-2) mod p.
pub fn mod_inv(a: &U256, p: &U256) -> U256 {
    let two: U256 = [2, 0, 0, 0];
    let exp = sub(p, &two).0;
    mod_pow(a, &exp, p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_no_carry() {
        let a: U256 = [1, 0, 0, 0];
        let b: U256 = [2, 0, 0, 0];
        let (r, c) = add(&a, &b);
        assert_eq!(r, [3, 0, 0, 0]);
        assert!(!c);
    }

    #[test]
    fn test_add_carry() {
        let a: U256 = [u64::MAX, 0, 0, 0];
        let b: U256 = [1, 0, 0, 0];
        let (r, c) = add(&a, &b);
        assert_eq!(r, [0, 1, 0, 0]);
        assert!(!c);
    }

    #[test]
    fn test_sub_no_borrow() {
        let a: U256 = [5, 0, 0, 0];
        let b: U256 = [3, 0, 0, 0];
        let (r, borrow) = sub(&a, &b);
        assert_eq!(r, [2, 0, 0, 0]);
        assert!(!borrow);
    }

    #[test]
    fn test_mod_mul_small() {
        let a: U256 = [7, 0, 0, 0];
        let b: U256 = [6, 0, 0, 0];
        let p: U256 = [11, 0, 0, 0];
        // 7 * 6 = 42 mod 11 = 9
        assert_eq!(mod_mul(&a, &b, &p), [9, 0, 0, 0]);
    }

    #[test]
    fn test_mod_inv_small() {
        let a: U256 = [3, 0, 0, 0];
        let p: U256 = [11, 0, 0, 0];
        let inv = mod_inv(&a, &p);
        // 3^(-1) mod 11 = 4 (since 3*4 = 12 = 1 mod 11)
        assert_eq!(inv, [4, 0, 0, 0]);
        assert_eq!(mod_mul(&a, &inv, &p), [1, 0, 0, 0]);
    }
}
