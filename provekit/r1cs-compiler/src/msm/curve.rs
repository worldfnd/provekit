use {
    ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField},
    provekit_common::FieldElement,
};

pub struct CurveParams {
    pub field_modulus_p: [u64; 4],
    pub curve_order_n:   [u64; 4],
    pub curve_a:         [u64; 4],
    pub curve_b:         [u64; 4],
    pub generator:       ([u64; 4], [u64; 4]),
    pub offset_point:    ([u64; 4], [u64; 4]),
}

impl CurveParams {
    /// Decompose the field modulus p into `num_limbs` limbs of `limb_bits`
    /// width each.
    pub fn p_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&self.field_modulus_p, limb_bits, num_limbs)
    }

    /// Decompose (p - 1) into `num_limbs` limbs of `limb_bits` width each.
    pub fn p_minus_1_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        let p_minus_1 = sub_one_u64_4(&self.field_modulus_p);
        decompose_to_limbs(&p_minus_1, limb_bits, num_limbs)
    }

    /// Decompose the curve parameter `a` into `num_limbs` limbs of `limb_bits`
    /// width.
    pub fn curve_a_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&self.curve_a, limb_bits, num_limbs)
    }

    /// Number of bits in the field modulus.
    pub fn modulus_bits(&self) -> u32 {
        if self.is_native_field() {
            FieldElement::MODULUS_BIT_SIZE
        } else {
            let p = &self.field_modulus_p;
            for i in (0..4).rev() {
                if p[i] != 0 {
                    return (i as u32) * 64 + (64 - p[i].leading_zeros());
                }
            }
            0
        }
    }

    /// Returns true if the curve's base field modulus equals the native BN254
    /// scalar field modulus.
    pub fn is_native_field(&self) -> bool {
        let native_mod = FieldElement::MODULUS;
        self.field_modulus_p == native_mod.0
    }

    /// Convert modulus to a native field element (only valid when p < native
    /// modulus).
    pub fn p_native_fe(&self) -> FieldElement {
        curve_native_point_fe(&self.field_modulus_p)
    }

    /// Decompose the curve order n into `num_limbs` limbs of `limb_bits` width
    /// each.
    pub fn curve_order_n_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&self.curve_order_n, limb_bits, num_limbs)
    }

    /// Decompose (curve_order_n - 1) into `num_limbs` limbs of `limb_bits`
    /// width each.
    pub fn curve_order_n_minus_1_limbs(
        &self,
        limb_bits: u32,
        num_limbs: usize,
    ) -> Vec<FieldElement> {
        let n_minus_1 = sub_one_u64_4(&self.curve_order_n);
        decompose_to_limbs(&n_minus_1, limb_bits, num_limbs)
    }

    /// Number of bits in the curve order n.
    pub fn curve_order_bits(&self) -> u32 {
        // Compute bit length directly from raw limbs to avoid reduction
        // mod the native field (curve_order_n may exceed the native modulus).
        let n = &self.curve_order_n;
        for i in (0..4).rev() {
            if n[i] != 0 {
                return (i as u32) * 64 + (64 - n[i].leading_zeros());
            }
        }
        0
    }

    /// Number of bits for the GLV half-scalar: `ceil(order_bits / 2)`.
    /// This determines the bit width of the sub-scalars s1, s2 from half-GCD.
    pub fn glv_half_bits(&self) -> u32 {
        (self.curve_order_bits() + 1) / 2
    }

    /// Decompose the generator x-coordinate into limbs.
    pub fn generator_x_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&self.generator.0, limb_bits, num_limbs)
    }

    /// Decompose the offset point x-coordinate into limbs.
    pub fn offset_x_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&self.offset_point.0, limb_bits, num_limbs)
    }

    /// Decompose the offset point y-coordinate into limbs.
    pub fn offset_y_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&self.offset_point.1, limb_bits, num_limbs)
    }

    /// Compute `[2^n_doublings] * offset_point` on the curve (compile-time
    /// only).
    ///
    /// Used to compute the accumulated offset after the scalar_mul_glv loop:
    /// since the accumulator starts at R and gets doubled n times total, the
    /// offset to subtract is `[2^n]*R`, not just `R`.
    pub fn accumulated_offset(&self, n_doublings: usize) -> ([u64; 4], [u64; 4]) {
        if self.is_native_field() {
            self.accumulated_offset_native(n_doublings)
        } else {
            self.accumulated_offset_generic(n_doublings)
        }
    }

    /// Compute accumulated offset using FieldElement arithmetic (native field).
    fn accumulated_offset_native(&self, n_doublings: usize) -> ([u64; 4], [u64; 4]) {
        let mut x = curve_native_point_fe(&self.offset_point.0);
        let mut y = curve_native_point_fe(&self.offset_point.1);
        let a = curve_native_point_fe(&self.curve_a);

        for _ in 0..n_doublings {
            let x_sq = x * x;
            let num = x_sq + x_sq + x_sq + a;
            let denom_inv = (y + y).inverse().unwrap();
            let lambda = num * denom_inv;
            let x3 = lambda * lambda - x - x;
            let y3 = lambda * (x - x3) - y;
            x = x3;
            y = y3;
        }

        (x.into_bigint().0, y.into_bigint().0)
    }

    /// Compute accumulated offset using generic 256-bit arithmetic (non-native
    /// field).
    fn accumulated_offset_generic(&self, n_doublings: usize) -> ([u64; 4], [u64; 4]) {
        let p = &self.field_modulus_p;
        let mut x = self.offset_point.0;
        let mut y = self.offset_point.1;
        let a = &self.curve_a;

        for _ in 0..n_doublings {
            let (x3, y3) = u256_arith::ec_point_double(&x, &y, a, p);
            x = x3;
            y = y3;
        }

        (x, y)
    }
}

/// Decompose a 256-bit value into `num_limbs` limbs of `limb_bits` width each,
/// returned as FieldElements.
pub fn decompose_to_limbs(val: &[u64; 4], limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
    // Special case: when a single limb needs > 128 bits, FieldElement::from(u128)
    // would truncate. Use from_sign_and_limbs to preserve the full value.
    if num_limbs == 1 && limb_bits > 128 {
        return vec![curve_native_point_fe(val)];
    }

    let mask: u128 = if limb_bits >= 128 {
        u128::MAX
    } else {
        (1u128 << limb_bits) - 1
    };
    let mut result = vec![FieldElement::from(0u64); num_limbs];
    let mut remaining = *val;
    for item in result.iter_mut() {
        let lo = remaining[0] as u128 | ((remaining[1] as u128) << 64);
        *item = FieldElement::from(lo & mask);
        // Shift remaining right by limb_bits
        if limb_bits >= 256 {
            remaining = [0; 4];
        } else {
            let mut shifted = [0u64; 4];
            let word_shift = (limb_bits / 64) as usize;
            let bit_shift = limb_bits % 64;
            for i in 0..4 {
                if i + word_shift < 4 {
                    shifted[i] = remaining[i + word_shift] >> bit_shift;
                    if bit_shift > 0 && i + word_shift + 1 < 4 {
                        shifted[i] |= remaining[i + word_shift + 1] << (64 - bit_shift);
                    }
                }
            }
            remaining = shifted;
        }
    }
    result
}

/// Subtract 1 from a [u64; 4] value.
fn sub_one_u64_4(val: &[u64; 4]) -> [u64; 4] {
    let mut result = *val;
    for limb in result.iter_mut() {
        if *limb > 0 {
            *limb -= 1;
            return result;
        }
        *limb = u64::MAX; // borrow
    }
    result
}

/// Converts a 256-bit value ([u64; 4]) into a single native field element.
pub fn curve_native_point_fe(val: &[u64; 4]) -> FieldElement {
    FieldElement::from_sign_and_limbs(true, val)
}

/// Negate a field element: compute `-val mod p` (i.e., `p - val`).
/// Returns `[0; 4]` when `val` is zero.
pub fn negate_field_element(val: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    if *val == [0u64; 4] {
        return [0u64; 4];
    }
    // val is in [1, p-1], so p - val is in [1, p-1] — no borrow.
    let mut result = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (d1, b1) = modulus[i].overflowing_sub(val[i]);
        let (d2, b2) = d1.overflowing_sub(borrow as u64);
        result[i] = d2;
        borrow = b1 || b2;
    }
    debug_assert!(!borrow, "negate_field_element: val >= modulus");
    result
}

/// Grumpkin curve parameters.
///
/// Grumpkin is a cycle-companion curve for BN254: its base field is the BN254
/// scalar field, and its order is the BN254 base field order.
///
/// Equation: y² = x³ − 17  (a = 0, b = −17 mod p)
pub fn grumpkin_params() -> CurveParams {
    CurveParams {
        // BN254 scalar field modulus
        field_modulus_p: [
            0x43e1f593f0000001_u64,
            0x2833e84879b97091_u64,
            0xb85045b68181585d_u64,
            0x30644e72e131a029_u64,
        ],
        // BN254 base field modulus
        curve_order_n:   [
            0x3c208c16d87cfd47_u64,
            0x97816a916871ca8d_u64,
            0xb85045b68181585d_u64,
            0x30644e72e131a029_u64,
        ],
        curve_a:         [0; 4],
        // b = −17 mod p
        curve_b:         [
            0x43e1f593effffff0_u64,
            0x2833e84879b97091_u64,
            0xb85045b68181585d_u64,
            0x30644e72e131a029_u64,
        ],
        // Generator G = (1, sqrt(−16) mod p)
        generator:       ([1, 0, 0, 0], [
            0x833fc48d823f272c_u64,
            0x2d270d45f1181294_u64,
            0xcf135e7506a45d63_u64,
            0x0000000000000002_u64,
        ]),
        // Offset point = [2^128]G (large offset avoids collisions with small multiples of G)
        offset_point:    (
            [
                0x626578b496650e95_u64,
                0x8678dcf264df6c01_u64,
                0xf0b3eb7e6d02aba8_u64,
                0x223748a4c4edde75_u64,
            ],
            [
                0xb75fb4c26bcd4f35_u64,
                0x4d4ba4d97d5f99d9_u64,
                0xccab35fdbf52368a_u64,
                0x25b41c5f56f8472b_u64,
            ],
        ),
    }
}

/// 256-bit modular arithmetic for compile-time EC point computations.
/// Only used to precompute accumulated offset points; not performance-critical.
mod u256_arith {
    type U256 = [u64; 4];

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offset_point_on_curve_grumpkin() {
        let c = grumpkin_params();
        let x = curve_native_point_fe(&c.offset_point.0);
        let y = curve_native_point_fe(&c.offset_point.1);
        let b = curve_native_point_fe(&c.curve_b);
        // Grumpkin: y^2 = x^3 + b (a=0)
        assert_eq!(y * y, x * x * x + b, "offset point not on Grumpkin");
    }

    #[test]
    fn test_accumulated_offset_single_double_grumpkin() {
        let c = grumpkin_params();
        let (x4, y4) = c.accumulated_offset(1);
        let x = curve_native_point_fe(&x4);
        let y = curve_native_point_fe(&y4);
        let b = curve_native_point_fe(&c.curve_b);
        // Should still be on curve
        assert_eq!(y * y, x * x * x + b, "[4]G not on Grumpkin");
    }

    #[test]
    fn test_accumulated_offset_native_vs_generic() {
        let c = grumpkin_params();
        // Both paths should give the same result
        let native = c.accumulated_offset_native(10);
        let generic = c.accumulated_offset_generic(10);
        assert_eq!(native, generic, "native vs generic mismatch for n=10");
    }

    #[test]
    fn test_accumulated_offset_256_on_curve() {
        let c = grumpkin_params();
        let (x, y) = c.accumulated_offset(256);
        let xfe = curve_native_point_fe(&x);
        let yfe = curve_native_point_fe(&y);
        let b = curve_native_point_fe(&c.curve_b);
        assert_eq!(yfe * yfe, xfe * xfe * xfe + b, "[2^257]G not on Grumpkin");
    }

    #[test]
    fn test_offset_point_on_curve_secp256r1() {
        let c = secp256r1_params();
        let p = &c.field_modulus_p;
        let x = &c.offset_point.0;
        let y = &c.offset_point.1;
        let a = &c.curve_a;
        let b = &c.curve_b;
        // y^2 = x^3 + a*x + b (mod p)
        let y_sq = u256_arith::mod_mul(y, y, p);
        let x_sq = u256_arith::mod_mul(x, x, p);
        let x_cubed = u256_arith::mod_mul(&x_sq, x, p);
        let ax = u256_arith::mod_mul(a, x, p);
        let x3_plus_ax = u256_arith::mod_add(&x_cubed, &ax, p);
        let rhs = u256_arith::mod_add(&x3_plus_ax, b, p);
        assert_eq!(y_sq, rhs, "offset point not on secp256r1");
    }

    #[test]
    fn test_accumulated_offset_secp256r1() {
        let c = secp256r1_params();
        let p = &c.field_modulus_p;
        let a = &c.curve_a;
        let b = &c.curve_b;
        let (x, y) = c.accumulated_offset(256);
        // Verify the accumulated offset is on the curve
        let y_sq = u256_arith::mod_mul(&y, &y, p);
        let x_sq = u256_arith::mod_mul(&x, &x, p);
        let x_cubed = u256_arith::mod_mul(&x_sq, &x, p);
        let ax = u256_arith::mod_mul(a, &x, p);
        let x3_plus_ax = u256_arith::mod_add(&x_cubed, &ax, p);
        let rhs = u256_arith::mod_add(&x3_plus_ax, b, p);
        assert_eq!(y_sq, rhs, "accumulated offset not on secp256r1");
    }

    #[test]
    fn test_fe_roundtrip() {
        // Verify from_sign_and_limbs / into_bigint roundtrip
        let val: [u64; 4] = [42, 0, 0, 0];
        let fe = curve_native_point_fe(&val);
        let back = fe.into_bigint().0;
        assert_eq!(val, back, "roundtrip failed for small value");

        let val2: [u64; 4] = [
            0x6d8bc688cdbffffe,
            0x19a74caa311e13d4,
            0xddeb49cdaa36306d,
            0x06ce1b0827aafa85,
        ];
        let fe2 = curve_native_point_fe(&val2);
        let back2 = fe2.into_bigint().0;
        assert_eq!(val2, back2, "roundtrip failed for offset x");
    }
}

#[allow(dead_code)]
pub fn secp256r1_params() -> CurveParams {
    CurveParams {
        field_modulus_p: [
            0xffffffffffffffff_u64,
            0xffffffff_u64,
            0x0_u64,
            0xffffffff00000001_u64,
        ],
        curve_order_n:   [
            0xf3b9cac2fc632551_u64,
            0xbce6faada7179e84_u64,
            0xffffffffffffffff_u64,
            0xffffffff00000000_u64,
        ],
        curve_a:         [
            0xfffffffffffffffc_u64,
            0x00000000ffffffff_u64,
            0x0000000000000000_u64,
            0xffffffff00000001_u64,
        ],
        curve_b:         [
            0x3bce3c3e27d2604b_u64,
            0x651d06b0cc53b0f6_u64,
            0xb3ebbd55769886bc_u64,
            0x5ac635d8aa3a93e7_u64,
        ],
        generator:       (
            [
                0xf4a13945d898c296_u64,
                0x77037d812deb33a0_u64,
                0xf8bce6e563a440f2_u64,
                0x6b17d1f2e12c4247_u64,
            ],
            [
                0xcbb6406837bf51f5_u64,
                0x2bce33576b315ece_u64,
                0x8ee7eb4a7c0f9e16_u64,
                0x4fe342e2fe1a7f9b_u64,
            ],
        ),
        // Offset point = [2^128]G (large offset avoids collisions with small multiples of G)
        offset_point:    (
            [
                0x57c84fc9d789bd85_u64,
                0xfc35ff7dc297eac3_u64,
                0xfb982fd588c6766e_u64,
                0x447d739beedb5e67_u64,
            ],
            [
                0x0c7e33c972e25b32_u64,
                0x3d349b95a7fae500_u64,
                0xe12e9d953a4aaff7_u64,
                0x2d4825ab834131ee_u64,
            ],
        ),
    }
}
