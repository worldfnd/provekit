//! 256-bit modular arithmetic for compile-time EC point computations.
//! Only used to precompute accumulated offset points; not performance-critical.

pub(super) type U256 = [u64; 4];

/// Returns true if a >= b.
fn gte(a: &U256, b: &U256) -> bool {
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
fn add(a: &U256, b: &U256) -> (U256, bool) {
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
fn sub(a: &U256, b: &U256) -> (U256, bool) {
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
fn mod_sub(a: &U256, b: &U256, p: &U256) -> U256 {
    let (d, borrow) = sub(a, b);
    if borrow {
        add(&d, p).0
    } else {
        d
    }
}

/// Schoolbook multiplication producing 512-bit result.
fn mul_wide(a: &U256, b: &U256) -> [u64; 8] {
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

/// Reduce a 512-bit value mod a 256-bit prime using bit-by-bit long
/// division.
fn mod_reduce_wide(a: &[u64; 8], p: &U256) -> U256 {
    let mut total_bits = 0;
    for i in (0..8).rev() {
        if a[i] != 0 {
            total_bits = i * 64 + (64 - a[i].leading_zeros() as usize);
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

        // Insert current bit of a
        let word = bit_idx / 64;
        let bit = bit_idx % 64;
        r[0] |= (a[word] >> bit) & 1;

        // If r >= p (or overflow from shift), subtract p
        if overflow != 0 || gte(&r, p) {
            r = sub(&r, p).0;
        }
    }
    r
}

/// (a * b) mod p.
pub fn mod_mul(a: &U256, b: &U256, p: &U256) -> U256 {
    let wide = mul_wide(a, b);
    mod_reduce_wide(&wide, p)
}

/// a^exp mod p using square-and-multiply.
fn mod_pow(base: &U256, exp: &U256, p: &U256) -> U256 {
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
fn mod_inv(a: &U256, p: &U256) -> U256 {
    let two: U256 = [2, 0, 0, 0];
    let exp = sub(p, &two).0;
    mod_pow(a, &exp, p)
}

/// EC point doubling on y^2 = x^3 + ax + b.
pub fn ec_point_double(x: &U256, y: &U256, a: &U256, p: &U256) -> (U256, U256) {
    // lambda = (3*x^2 + a) / (2*y)
    let x_sq = mod_mul(x, x, p);
    let two_x_sq = mod_add(&x_sq, &x_sq, p);
    let three_x_sq = mod_add(&two_x_sq, &x_sq, p);
    let num = mod_add(&three_x_sq, a, p);
    let two_y = mod_add(y, y, p);
    let denom_inv = mod_inv(&two_y, p);
    let lambda = mod_mul(&num, &denom_inv, p);

    // x3 = lambda^2 - 2*x
    let lambda_sq = mod_mul(&lambda, &lambda, p);
    let two_x = mod_add(x, x, p);
    let x3 = mod_sub(&lambda_sq, &two_x, p);

    // y3 = lambda * (x - x3) - y
    let x_minus_x3 = mod_sub(x, &x3, p);
    let lambda_dx = mod_mul(&lambda, &x_minus_x3, p);
    let y3 = mod_sub(&lambda_dx, y, p);

    (x3, y3)
}
