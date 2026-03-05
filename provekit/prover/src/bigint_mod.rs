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

/// Add two 4-limb numbers in-place: a += b. Returns the carry-out.
pub fn add_4limb_inplace(a: &mut [u64; 4], b: &[u64; 4]) -> u64 {
    let mut carry = 0u64;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        a[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
    }
    carry
}

/// Subtract b from a in-place, returning true if a >= b (no underflow).
/// If a < b, the result is a += 2^256 - b (wrapping subtraction) and returns
/// false.
pub fn sub_4limb_checked(a: &mut [u64; 4], b: &[u64; 4]) -> bool {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        a[i] = d2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    borrow == 0
}

/// Returns true if val == 0.
pub fn is_zero(val: &[u64; 4]) -> bool {
    val[0] == 0 && val[1] == 0 && val[2] == 0 && val[3] == 0
}

/// Compute the number of bits needed for the half-GCD sub-scalars.
/// Returns `ceil(order_bits / 2)` where `order_bits` is the bit length of `n`.
pub fn half_gcd_bits(n: &[u64; 4]) -> u32 {
    let mut order_bits = 0u32;
    for i in (0..4).rev() {
        if n[i] != 0 {
            order_bits = (i as u32) * 64 + (64 - n[i].leading_zeros());
            break;
        }
    }
    (order_bits + 1) / 2
}

/// Build the threshold value `2^half_bits` as a `[u64; 4]`.
fn build_threshold(half_bits: u32) -> [u64; 4] {
    assert!(half_bits <= 255, "half_bits must be <= 255");
    let mut threshold = [0u64; 4];
    let word = (half_bits / 64) as usize;
    let bit = half_bits % 64;
    threshold[word] = 1u64 << bit;
    threshold
}

/// Half-GCD scalar decomposition for FakeGLV.
///
/// Given scalar `s` and curve order `n`, finds `(|s1|, |s2|, neg1, neg2)` such
/// that:   `(-1)^neg1 * |s1| + (-1)^neg2 * |s2| * s ≡ 0 (mod n)`
///
/// Uses the extended GCD on `(n, s)`, stopping when the remainder drops below
/// `2^half_bits` where `half_bits = ceil(order_bits / 2)`.
/// Returns `(val1, val2, neg1, neg2)` where both fit in `half_bits` bits.
pub fn half_gcd(s: &[u64; 4], n: &[u64; 4]) -> ([u64; 4], [u64; 4], bool, bool) {
    // Extended GCD on (n, s):
    // We track: r_{i} = r_{i-2} - q_i * r_{i-1}
    //           t_{i} = t_{i-2} - q_i * t_{i-1}
    // Starting: r_0 = n, r_1 = s, t_0 = 0, t_1 = 1
    //
    // We want: t_i * s ≡ r_i (mod n) [up to sign]
    // More precisely: t_i * s ≡ (-1)^{i+1} * r_i (mod n)
    //
    // The relation we verify is: sign_r * |r_i| + sign_t * |t_i| * s ≡ 0 (mod n)

    // Threshold: 2^half_bits where half_bits = ceil(order_bits / 2)
    let half_bits = half_gcd_bits(n);
    let threshold = build_threshold(half_bits);

    // r_prev = n, r_curr = s
    let mut r_prev = *n;
    let mut r_curr = *s;

    // t_prev = 0, t_curr = 1
    let mut t_prev = [0u64; 4];
    let mut t_curr = [1u64, 0, 0, 0];

    // Track sign of t: t_prev_neg=false (t_0=0, positive), t_curr_neg=false (t_1=1,
    // positive)
    let mut t_prev_neg = false;
    let mut t_curr_neg = false;

    let mut iteration = 0u32;

    loop {
        // Check if r_curr < threshold
        if cmp_4limb(&r_curr, &threshold) == std::cmp::Ordering::Less {
            break;
        }

        if is_zero(&r_curr) {
            break;
        }

        // q = r_prev / r_curr, new_r = r_prev % r_curr
        let (q, new_r) = divmod(&r_prev, &r_curr);

        // new_t = t_prev + q * t_curr (in terms of absolute values and signs)
        // Since the GCD recurrence is: t_{i} = t_{i-2} - q_i * t_{i-1}
        // In terms of absolute values with sign tracking:
        // If t_prev and q*t_curr have the same sign → subtract magnitudes
        // If they have different signs → add magnitudes
        // new_t = |t_prev| +/- q * |t_curr|, with sign flips each
        // iteration.
        //
        // The standard extended GCD recurrence gives:
        //   t_i = t_{i-2} - q_i * t_{i-1}
        // We track magnitudes and sign bits separately.

        // Compute q * t_curr
        let qt = mul_mod_no_reduce(&q, &t_curr);

        // new_t magnitude and sign:
        // In the standard recurrence: new_t_val = t_prev_val - q * t_curr_val
        // where t_prev_val = (-1)^t_prev_neg * |t_prev|, etc.
        //
        // But it's simpler to just track: alternating signs.
        // In the half-GCD: t values alternate in sign. So:
        // new_t = t_prev + q * t_curr (absolute addition since signs alternate)
        let mut new_t = qt;
        add_4limb_inplace(&mut new_t, &t_prev);
        let new_t_neg = !t_curr_neg;

        r_prev = r_curr;
        r_curr = new_r;
        t_prev = t_curr;
        t_prev_neg = t_curr_neg;
        t_curr = new_t;
        t_curr_neg = new_t_neg;
        iteration += 1;
    }

    // At this point: r_curr < 2^half_bits and t_curr < ~2^half_bits (half-GCD
    // property) The relation is: (-1)^(iteration) * r_curr + t_curr * s ≡ 0
    // (mod n) Or equivalently: r_curr ≡ (-1)^(iteration+1) * t_curr * s (mod n)

    let val1 = r_curr; // |s1| = |r_i|
    let val2 = t_curr; // |s2| = |t_i|

    // Determine signs:
    // We need: neg1 * val1 + neg2 * val2 * s ≡ 0 (mod n)
    // From the extended GCD: r_i = (-1)^i * (... some relation with t_i * s mod n)
    // The exact sign relationship:
    // t_i * s ≡ (-1)^(i+1) * r_i (mod n)
    // So: (-1)^(i+1) * r_i + t_i * s ≡ 0 (mod n)
    //
    // If iteration is even: (-1)^(even+1) = -1, so: -r_i + t_i * s ≡ 0
    //   → neg1=true (negate r_i), neg2=t_curr_neg
    // If iteration is odd: (-1)^(odd+1) = 1, so: r_i + t_i * s ≡ 0
    //   → neg1=false, neg2=t_curr_neg

    let neg1 = iteration % 2 == 0; // negate val1 when iteration is even
    let neg2 = t_curr_neg;

    (val1, val2, neg1, neg2)
}

/// Multiply two 4-limb values without modular reduction.
/// Returns the lower 4 limbs (ignoring overflow beyond 256 bits).
/// Used internally by half_gcd for q * t_curr where the result is known to fit.
fn mul_mod_no_reduce(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let wide = widening_mul(a, b);
    [wide[0], wide[1], wide[2], wide[3]]
}

// ---------------------------------------------------------------------------
// Modular arithmetic helpers for EC operations (prover-side)
// ---------------------------------------------------------------------------

/// Modular addition: (a + b) mod p.
pub fn mod_add(a: &[u64; 4], b: &[u64; 4], p: &[u64; 4]) -> [u64; 4] {
    let sum = add_4limb(a, b);
    let sum4 = [sum[0], sum[1], sum[2], sum[3]];
    if sum[4] > 0 || cmp_4limb(&sum4, p) != std::cmp::Ordering::Less {
        // sum >= p, subtract p
        let mut result = sum4;
        sub_4limb_inplace(&mut result, p);
        result
    } else {
        sum4
    }
}

/// Modular subtraction: (a - b) mod p.
pub fn mod_sub(a: &[u64; 4], b: &[u64; 4], p: &[u64; 4]) -> [u64; 4] {
    let mut result = *a;
    let no_borrow = sub_4limb_checked(&mut result, b);
    if no_borrow {
        result
    } else {
        // a < b, add p to get (a - b + p)
        add_4limb_inplace(&mut result, p);
        result
    }
}

/// Modular inverse: a^{p-2} mod p (Fermat's little theorem).
pub fn mod_inverse(a: &[u64; 4], p: &[u64; 4]) -> [u64; 4] {
    let exp = sub_u64(p, 2);
    mod_pow(a, &exp, p)
}

/// EC point doubling in affine coordinates on y^2 = x^3 + ax + b.
/// Returns (x3, y3) = 2*(px, py).
pub fn ec_point_double(
    px: &[u64; 4],
    py: &[u64; 4],
    a: &[u64; 4],
    p: &[u64; 4],
) -> ([u64; 4], [u64; 4]) {
    // lambda = (3*x^2 + a) / (2*y)
    let x_sq = mul_mod(px, px, p);
    let two_x_sq = mod_add(&x_sq, &x_sq, p);
    let three_x_sq = mod_add(&two_x_sq, &x_sq, p);
    let numerator = mod_add(&three_x_sq, a, p);
    let two_y = mod_add(py, py, p);
    let denom_inv = mod_inverse(&two_y, p);
    let lambda = mul_mod(&numerator, &denom_inv, p);

    // x3 = lambda^2 - 2*x
    let lambda_sq = mul_mod(&lambda, &lambda, p);
    let two_x = mod_add(px, px, p);
    let x3 = mod_sub(&lambda_sq, &two_x, p);

    // y3 = lambda * (x - x3) - y
    let x_minus_x3 = mod_sub(px, &x3, p);
    let lambda_dx = mul_mod(&lambda, &x_minus_x3, p);
    let y3 = mod_sub(&lambda_dx, py, p);

    (x3, y3)
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
    // lambda = (y2 - y1) / (x2 - x1)
    let numerator = mod_sub(p2y, p1y, p);
    let denominator = mod_sub(p2x, p1x, p);
    let denom_inv = mod_inverse(&denominator, p);
    let lambda = mul_mod(&numerator, &denom_inv, p);

    // x3 = lambda^2 - x1 - x2
    let lambda_sq = mul_mod(&lambda, &lambda, p);
    let x1_plus_x2 = mod_add(p1x, p2x, p);
    let x3 = mod_sub(&lambda_sq, &x1_plus_x2, p);

    // y3 = lambda * (x1 - x3) - y1
    let x1_minus_x3 = mod_sub(p1x, &x3, p);
    let lambda_dx = mul_mod(&lambda, &x1_minus_x3, p);
    let y3 = mod_sub(&lambda_dx, p1y, p);

    (x3, y3)
}

/// EC scalar multiplication via double-and-add: returns [scalar]*P.
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
    fn test_half_gcd_small() {
        // s = 42, n = 101
        let s = [42, 0, 0, 0];
        let n = [101, 0, 0, 0];
        let (val1, val2, neg1, neg2) = half_gcd(&s, &n);

        // Verify: (-1)^neg1 * val1 + (-1)^neg2 * val2 * s ≡ 0 (mod n)
        let sign1: i128 = if neg1 { -1 } else { 1 };
        let sign2: i128 = if neg2 { -1 } else { 1 };
        let v1 = val1[0] as i128;
        let v2 = val2[0] as i128;
        let s_val = s[0] as i128;
        let n_val = n[0] as i128;
        let lhs = ((sign1 * v1 + sign2 * v2 * s_val) % n_val + n_val) % n_val;
        assert_eq!(lhs, 0, "half_gcd relation failed for small values");
    }

    #[test]
    fn test_half_gcd_grumpkin_order() {
        // Grumpkin curve order (BN254 base field order)
        let n = [
            0x3c208c16d87cfd47_u64,
            0x97816a916871ca8d_u64,
            0xb85045b68181585d_u64,
            0x30644e72e131a029_u64,
        ];
        // Some scalar
        let s = [
            0x123456789abcdef0_u64,
            0xfedcba9876543210_u64,
            0x1111111111111111_u64,
            0x2222222222222222_u64,
        ];

        let (val1, val2, neg1, neg2) = half_gcd(&s, &n);

        // val1 and val2 should be < 2^128
        assert_eq!(val1[2], 0, "val1 should be < 2^128");
        assert_eq!(val1[3], 0, "val1 should be < 2^128");
        assert_eq!(val2[2], 0, "val2 should be < 2^128");
        assert_eq!(val2[3], 0, "val2 should be < 2^128");

        // Verify: (-1)^neg1 * val1 + (-1)^neg2 * val2 * s ≡ 0 (mod n)
        // Use big integer arithmetic
        let term2_full = widening_mul(&val2, &s);
        let (_, term2_mod_n) = divmod_wide(&term2_full, &n);

        // Compute: sign1 * val1 + sign2 * term2_mod_n (mod n)
        let effective1 = if neg1 {
            // n - val1
            let mut result = n;
            sub_4limb_checked(&mut result, &val1);
            result
        } else {
            val1
        };
        let effective2 = if neg2 {
            let mut result = n;
            sub_4limb_checked(&mut result, &term2_mod_n);
            result
        } else {
            term2_mod_n
        };

        let sum = add_4limb(&effective1, &effective2);
        let sum4 = [sum[0], sum[1], sum[2], sum[3]];
        // sum might be >= n, so reduce
        let (_, remainder) = if sum[4] > 0 {
            // Sum overflows 256 bits, need wide divmod
            let wide = [sum[0], sum[1], sum[2], sum[3], sum[4], 0, 0, 0];
            divmod_wide(&wide, &n)
        } else {
            divmod(&sum4, &n)
        };
        assert_eq!(
            remainder,
            [0, 0, 0, 0],
            "half_gcd relation failed for Grumpkin order"
        );
    }
}
