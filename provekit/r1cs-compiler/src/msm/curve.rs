use {
    ark_ff::{BigInteger, PrimeField},
    provekit_common::FieldElement,
};

pub struct CurveParams {
    pub field_modulus_p: [u64; 4],
    pub curve_order_n:   [u64; 4],
    pub curve_a:         [u64; 4],
    pub curve_b:         [u64; 4],
    pub generator:       ([u64; 4], [u64; 4]),
}

impl CurveParams {
    /// Decompose the field modulus p into `num_limbs` limbs of `limb_bits` width each.
    pub fn p_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&self.field_modulus_p, limb_bits, num_limbs)
    }

    /// Decompose (p - 1) into `num_limbs` limbs of `limb_bits` width each.
    pub fn p_minus_1_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        let p_minus_1 = sub_one_u64_4(&self.field_modulus_p);
        decompose_to_limbs(&p_minus_1, limb_bits, num_limbs)
    }

    /// Decompose the curve parameter `a` into `num_limbs` limbs of `limb_bits` width.
    pub fn curve_a_limbs(&self, limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
        decompose_to_limbs(&self.curve_a, limb_bits, num_limbs)
    }

    /// Number of bits in the field modulus.
    pub fn modulus_bits(&self) -> u32 {
        if self.is_native_field() {
            // p mod p = 0 as a field element, so we use the constant directly.
            FieldElement::MODULUS_BIT_SIZE
        } else {
            let fe = curve_native_point_fe(&self.field_modulus_p);
            fe.into_bigint().num_bits()
        }
    }

    /// Returns true if the curve's base field modulus equals the native BN254
    /// scalar field modulus.
    pub fn is_native_field(&self) -> bool {
        let native_mod = FieldElement::MODULUS;
        self.field_modulus_p == native_mod.0
    }

    /// Convert modulus to a native field element (only valid when p < native modulus).
    pub fn p_native_fe(&self) -> FieldElement {
        curve_native_point_fe(&self.field_modulus_p)
    }
}

/// Decompose a 256-bit value into `num_limbs` limbs of `limb_bits` width each,
/// returned as FieldElements.
fn decompose_to_limbs(val: &[u64; 4], limb_bits: u32, num_limbs: usize) -> Vec<FieldElement> {
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
        curve_order_n: [
            0x3c208c16d87cfd47_u64,
            0x97816a916871ca8d_u64,
            0xb85045b68181585d_u64,
            0x30644e72e131a029_u64,
        ],
        curve_a: [0; 4],
        // b = −17 mod p
        curve_b: [
            0x43e1f593effffff0_u64,
            0x2833e84879b97091_u64,
            0xb85045b68181585d_u64,
            0x30644e72e131a029_u64,
        ],
        // Generator G = (1, sqrt(−16) mod p)
        generator: (
            [1, 0, 0, 0],
            [
                0x833fc48d823f272c_u64,
                0x2d270d45f1181294_u64,
                0xcf135e7506a45d63_u64,
                0x0000000000000002_u64,
            ],
        ),
    }
}

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
    }
}
