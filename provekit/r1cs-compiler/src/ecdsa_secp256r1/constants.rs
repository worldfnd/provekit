use provekit_common::FieldElement;

// secp256r1 curve order n:
// 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
const CURVE_FR_N_LIMBS: [u64; 4] = [
    0xf3b9cac2fc632551_u64,
    0xbce6faada7179e84_u64,
    0xffffffffffffffff_u64,
    0xffffffff00000000_u64,
];

// secp256r1 field modulus p:
// 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
const CURVE_FP_P_LIMBS: [u64; 4] = [
    0xffffffffffffffff_u64,
    0xffffffff_u64,
    0x0_u64,
    0xffffffff00000001_u64,
];

// secp256r1 curve parameter b:
// 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
const CURVE_B_LIMBS: [u64; 4] = [
    0x3bce3c3e27d2604b_u64,
    0x651d06b0cc53b0f6_u64,
    0xb3ebbd55769886bc_u64,
    0x5ac635d8aa3a93e7_u64,
];

/// secp256r1 generator point G x-coordinate:
/// x = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
const CURVE_GENERATOR_X_LIMBS: [u64; 4] = [
    0xf4a13945d898c296_u64,
    0x77037d812deb33a0_u64,
    0xf8bce6e563a440f2_u64,
    0x6b17d1f2e12c4247_u64,
];

/// secp256r1 generator point G y-coordinate:
/// y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
const CURVE_GENERATOR_Y_LIMBS: [u64; 4] = [
    0xcbb6406837bf51f5_u64,
    0x2bce33576b315ece_u64,
    0x8ee7eb4a7c0f9e16_u64,
    0x4fe342e2fe1a7f9b_u64,
];

/// Get the secp256r1 curve order n as a FieldElement
pub(crate) fn get_curve_order_n() -> FieldElement {
    FieldElement::from_sign_and_limbs(true, &CURVE_FR_N_LIMBS)
}

/// Get the secp256r1 field modulus p as a FieldElement
pub(crate) fn get_curve_field_modulus_p() -> FieldElement {
    FieldElement::from_sign_and_limbs(true, &CURVE_FP_P_LIMBS)
}

/// Get the secp256r1 curve parameter b as a FieldElement
pub(crate) fn get_curve_parameter_b() -> FieldElement {
    FieldElement::from_sign_and_limbs(true, &CURVE_B_LIMBS)
}

/// Get the secp256r1 generator point G as a FieldElement
pub(crate) fn get_generator_point() -> (FieldElement, FieldElement) {
    let gx = FieldElement::from_sign_and_limbs(true, &CURVE_GENERATOR_X_LIMBS);
    let gy = FieldElement::from_sign_and_limbs(true, &CURVE_GENERATOR_Y_LIMBS);
    (gx, gy)
}
