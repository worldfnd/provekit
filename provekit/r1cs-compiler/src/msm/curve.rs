use {
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    provekit_common::{
        witness::{ConstantTerm, WitnessBuilder},
        FieldElement,
    },
};

pub struct CurveParams {
    pub field_modulus_p: [u64; 4],
    pub curve_order_n:   [u64; 4],
    pub curve_a:         [u64; 4],
    pub curve_b:         [u64; 4],
    pub generator:       ([u64; 4], [u64; 4]),
}

impl CurveParams {
    pub fn p_lo_fe(&self) -> FieldElement {
        decompose_128(self.field_modulus_p).0
    }
    pub fn p_hi_fe(&self) -> FieldElement {
        decompose_128(self.field_modulus_p).1
    }
    pub fn p_86_limbs(&self) -> [FieldElement; 3] {
        let mask_86: u128 = (1u128 << 86) - 1;
        let lo128 = self.field_modulus_p[0] as u128 | ((self.field_modulus_p[1] as u128) << 64);
        let hi128 = self.field_modulus_p[2] as u128 | ((self.field_modulus_p[3] as u128) << 64);
        let l0 = lo128 & mask_86;
        // l1 spans bits [86..172): 42 bits from lo128, 44 bits from hi128
        let l1 = ((lo128 >> 86) | (hi128 << 42)) & mask_86;
        // l2 = bits [172..256): 84 bits from hi128
        let l2 = hi128 >> 44;
        [
            FieldElement::from(l0),
            FieldElement::from(l1),
            FieldElement::from(l2),
        ]
    }
    pub fn p_native_fe(&self) -> FieldElement {
        curve_native_point_fe(&self.field_modulus_p)
    }
}

/// Splits a 256-bit value ([u64; 4]) into two 128-bit field elements (lo, hi).
fn decompose_128(val: [u64; 4]) -> (FieldElement, FieldElement) {
    (
        FieldElement::from((val[0] as u128) | ((val[1] as u128) << 64)),
        FieldElement::from((val[2] as u128) | ((val[3] as u128) << 64)),
    )
}

/// Converts a 256-bit value ([u64; 4]) into a single native field element.
pub fn curve_native_point_fe(val: &[u64; 4]) -> FieldElement {
    FieldElement::from_sign_and_limbs(true, val)
}

#[derive(Clone, Copy, Debug)]
pub struct Limb2 {
    pub lo: usize,
    pub hi: usize,
}

pub fn limb2_constant(r1cs_compiler: &mut NoirToR1CSCompiler, value: [u64; 4]) -> Limb2 {
    let (lo, hi) = decompose_128(value);
    let lo_idx = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Constant(ConstantTerm(lo_idx, lo)));
    let hi_idx = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Constant(ConstantTerm(hi_idx, hi)));
    Limb2 {
        lo: lo_idx,
        hi: hi_idx,
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
