use {
    ark_ff::{AdditiveGroup, PrimeField},
    provekit_common::FieldElement,
};

mod grumpkin;
mod secp256r1;
mod u256_arith;

pub use {grumpkin::Grumpkin, provekit_common::u256_arith::U256, secp256r1::Secp256r1};

// ---------------------------------------------------------------------------
// Curve trait — the only thing a new curve needs to implement
// ---------------------------------------------------------------------------

/// Elliptic curve definition for MSM circuit compilation.
///
/// Each supported curve is a zero-sized struct implementing this trait.
/// Only the 6 required methods (curve constants) must be provided;
/// all derived properties and decomposition helpers have default
/// implementations.
pub trait Curve {
    // ===== Required: curve constants =====

    /// Base field modulus p as 4 × u64 limbs (256-bit, little-endian).
    fn field_modulus_p(&self) -> U256;
    /// Scalar field order n as 4 × u64 limbs.
    fn curve_order_n(&self) -> U256;
    /// Weierstrass curve parameter a.
    fn curve_a(&self) -> U256;
    /// Weierstrass curve parameter b.
    fn curve_b(&self) -> U256;
    /// Generator point (x, y).
    fn generator(&self) -> (U256, U256);
    /// Offset point for accumulation (x, y).
    fn offset_point(&self) -> (U256, U256);

    // ===== Provided: derived properties =====

    /// Number of bits in the field modulus.
    fn modulus_bits(&self) -> u32 {
        bit_length_u256(&self.field_modulus_p())
    }

    /// Returns true if the curve's base field equals the native field
    /// (currently BN254 scalar field, but determined dynamically from
    /// `FieldElement::MODULUS`).
    fn is_native_field(&self) -> bool {
        self.field_modulus_p() == FieldElement::MODULUS.0
    }

    /// Number of bits in the curve order n.
    fn curve_order_bits(&self) -> u32 {
        bit_length_u256(&self.curve_order_n())
    }

    /// Number of bits for the GLV half-scalar: `ceil(order_bits / 2)`.
    fn glv_half_bits(&self) -> u32 {
        (self.curve_order_bits() + 1) / 2
    }

    /// Convert modulus to a native field element.
    fn p_native_fe(&self) -> FieldElement {
        curve_native_point_fe(&self.field_modulus_p())
    }

    // ===== Provided: limb decomposition helpers =====

    fn p_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&self.field_modulus_p(), limb_bits, num_limbs)
    }
    fn p_minus_1_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(
            &sub_one_u64_4(&self.field_modulus_p()),
            limb_bits,
            num_limbs,
        )
    }
    fn curve_a_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&self.curve_a(), limb_bits, num_limbs)
    }
    fn curve_b_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&self.curve_b(), limb_bits, num_limbs)
    }
    fn curve_order_n_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&self.curve_order_n(), limb_bits, num_limbs)
    }
    fn curve_order_n_minus_1_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&sub_one_u64_4(&self.curve_order_n()), limb_bits, num_limbs)
    }
    fn generator_x_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&self.generator().0, limb_bits, num_limbs)
    }
    fn offset_x_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&self.offset_point().0, limb_bits, num_limbs)
    }
    fn offset_y_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&self.offset_point().1, limb_bits, num_limbs)
    }

    /// Compute `[2^n_doublings] * offset_point` on the curve (compile-time
    /// only).
    fn accumulated_offset(&self, n_doublings: usize) -> (U256, U256) {
        let p = self.field_modulus_p();
        let a = self.curve_a();
        let mut x = self.offset_point().0;
        let mut y = self.offset_point().1;
        for _ in 0..n_doublings {
            let (x3, y3) = u256_arith::ec_point_double(&x, &y, &a, &p);
            x = x3;
            y = y3;
        }
        (x, y)
    }
}

/// Compute bit length of a 256-bit value.
fn bit_length_u256(val: &U256) -> u32 {
    for i in (0..4).rev() {
        if val[i] != 0 {
            return (i as u32) * 64 + (64 - val[i].leading_zeros());
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Decompose a 256-bit value into `num_limbs` limbs of `limb_bits` width each,
/// returned as FieldElements.
pub fn decompose_to_limbs(val: &U256, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
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
    let mut result = vec![FieldElement::ZERO; num_limbs];
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

/// Subtract 1 from a U256 value.
fn sub_one_u64_4(val: &U256) -> U256 {
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
pub fn curve_native_point_fe(val: &U256) -> FieldElement {
    FieldElement::from_sign_and_limbs(true, val)
}

/// Negate a field element: compute `-val mod p` (i.e., `p - val`).
/// Returns `[0; 4]` when `val` is zero.
pub fn negate_field_element(val: &U256, modulus: &U256) -> U256 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offset_point_on_curve_grumpkin() {
        let c = Grumpkin;
        let x = curve_native_point_fe(&c.offset_point().0);
        let y = curve_native_point_fe(&c.offset_point().1);
        let b = curve_native_point_fe(&c.curve_b());
        // Grumpkin: y^2 = x^3 + b (a=0)
        assert_eq!(y * y, x * x * x + b, "offset point not on Grumpkin");
    }

    #[test]
    fn test_accumulated_offset_single_double_grumpkin() {
        let c = Grumpkin;
        let (x4, y4) = c.accumulated_offset(1);
        let x = curve_native_point_fe(&x4);
        let y = curve_native_point_fe(&y4);
        let b = curve_native_point_fe(&c.curve_b());
        // Should still be on curve
        assert_eq!(y * y, x * x * x + b, "[2]*offset not on Grumpkin");
    }

    #[test]
    fn test_accumulated_offset_256_on_curve() {
        let c = Grumpkin;
        let (x, y) = c.accumulated_offset(256);
        let xfe = curve_native_point_fe(&x);
        let yfe = curve_native_point_fe(&y);
        let b = curve_native_point_fe(&c.curve_b());
        assert_eq!(yfe * yfe, xfe * xfe * xfe + b, "[2^257]G not on Grumpkin");
    }

    #[test]
    fn test_offset_point_on_curve_secp256r1() {
        let c = Secp256r1;
        let p = &c.field_modulus_p();
        let x = &c.offset_point().0;
        let y = &c.offset_point().1;
        let a = &c.curve_a();
        let b = &c.curve_b();
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
        let c = Secp256r1;
        let p = &c.field_modulus_p();
        let a = &c.curve_a();
        let b = &c.curve_b();
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
