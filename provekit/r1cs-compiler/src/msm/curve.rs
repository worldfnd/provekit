use provekit_common::FieldElement;

// TODO : remove Option<> form both the params if comes in use
// otherwise we delete the params from struct
pub struct CurveParams {
    pub field_modulus_p: FieldElement,
    pub curve_order_n:   FieldElement,
    pub curve_a:         FieldElement,
    pub curve_b:         FieldElement,
    pub generator:       (FieldElement, FieldElement),
    pub coordinate_bits: Option<u32>,
}

pub fn secp256r1_params() -> CurveParams {
    CurveParams {
        field_modulus_p: FieldElement::from_sign_and_limbs(
            true,
            [
                0xffffffffffffffff_u64,
                0xffffffff_u64,
                0x0_u64,
                0xffffffff00000001_u64,
            ]
            .as_slice(),
        ),
        curve_order_n:   FieldElement::from_sign_and_limbs(
            true,
            [
                0xf3b9cac2fc632551_u64,
                0xbce6faada7179e84_u64,
                0xffffffffffffffff_u64,
                0xffffffff00000000_u64,
            ]
            .as_slice(),
        ),
        curve_a:         FieldElement::from(-3),
        curve_b:         FieldElement::from_sign_and_limbs(
            true,
            [
                0x3bce3c3e27d2604b_u64,
                0x651d06b0cc53b0f6_u64,
                0xb3ebbd55769886bc_u64,
                0x5ac635d8aa3a93e7_u64,
            ]
            .as_slice(),
        ),
        generator:       (
            FieldElement::from_sign_and_limbs(
                true,
                [
                    0xf4a13945d898c296_u64,
                    0x77037d812deb33a0_u64,
                    0xf8bce6e563a440f2_u64,
                    0x6b17d1f2e12c4247_u64,
                ]
                .as_slice(),
            ),
            FieldElement::from_sign_and_limbs(
                true,
                [
                    0xcbb6406837bf51f5_u64,
                    0x2bce33576b315ece_u64,
                    0x8ee7eb4a7c0f9e16_u64,
                    0x4fe342e2fe1a7f9b_u64,
                ]
                .as_slice(),
            ),
        ),
        coordinate_bits: None,
    }
}
