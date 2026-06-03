use bignum::BigNum;
use bigcurve::{
    BigCurve,
    curves::secp256r1::{Secp256r1, Secp256r1_Fq, Secp256r1_Fr, Secp256r1Scalar},
};
use sha256::sha256_var;

global AUTHENTICATOR_DATA_LEN: u32 = 37;
global CHALLENGE_COMMITMENT_LEN: u32 = 32;
global PASSKEY_SIGNED_MESSAGE_LEN: u32 = AUTHENTICATOR_DATA_LEN + CHALLENGE_COMMITMENT_LEN;
global P256_LIMBS: u32 = 3;
global P256_SCALAR_SLICES: u32 = 65;
global TWO_POW_120_FIELD: Field = 0x1000000000000000000000000000000;

fn main(
    authenticator_data: pub [u8; AUTHENTICATOR_DATA_LEN],
    challenge_commitment: pub [u8; CHALLENGE_COMMITMENT_LEN],
    pub_key_x: pub [u8; 32],
    pub_key_y: pub [u8; 32],
    signature: pub [u8; 64],
    challenge_secret: [u8; 32],
    r_point_y: [u8; 32],
    message_limbs: pub [Field; P256_LIMBS],
    pub_key_x_limbs: pub [Field; P256_LIMBS],
    pub_key_y_limbs: pub [Field; P256_LIMBS],
    signature_r_limbs: pub [Field; P256_LIMBS],
    signature_s_limbs: pub [Field; P256_LIMBS],
    r_point_y_limbs: pub [Field; P256_LIMBS],
    s_g_limbs: pub [Field; P256_LIMBS],
    s_g_slices: [u8; P256_SCALAR_SLICES],
    s_g_skew: bool,
    s_g_borrow_low: bool,
    s_g_borrow_mid: bool,
    s_p_limbs: pub [Field; P256_LIMBS],
    s_p_slices: [u8; P256_SCALAR_SLICES],
    s_p_skew: bool,
    s_p_borrow_low: bool,
    s_p_borrow_mid: bool,
) {
    let computed_commitment = sha256_var(challenge_secret, CHALLENGE_COMMITMENT_LEN);
    for i in 0..CHALLENGE_COMMITMENT_LEN {
        assert(computed_commitment[i] == challenge_commitment[i]);
    }

    let mut signed_message: [u8; PASSKEY_SIGNED_MESSAGE_LEN] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    for i in 0..AUTHENTICATOR_DATA_LEN {
        signed_message[i] = authenticator_data[i];
    }
    for i in 0..CHALLENGE_COMMITMENT_LEN {
        signed_message[AUTHENTICATOR_DATA_LEN + i] = challenge_commitment[i];
    }

    let signed_message_digest = sha256_var(signed_message, PASSKEY_SIGNED_MESSAGE_LEN);
    verify_p256_signature(
        signed_message_digest,
        pub_key_x,
        pub_key_y,
        signature,
        r_point_y,
        field_limbs_to_u128(message_limbs),
        field_limbs_to_u128(pub_key_x_limbs),
        field_limbs_to_u128(pub_key_y_limbs),
        field_limbs_to_u128(signature_r_limbs),
        field_limbs_to_u128(signature_s_limbs),
        field_limbs_to_u128(r_point_y_limbs),
        field_limbs_to_u128(s_g_limbs),
        s_g_slices,
        s_g_skew,
        s_g_borrow_low,
        s_g_borrow_mid,
        field_limbs_to_u128(s_p_limbs),
        s_p_slices,
        s_p_skew,
        s_p_borrow_low,
        s_p_borrow_mid,
    );
}

fn verify_p256_signature(
    signed_message_digest: [u8; 32],
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    r_point_y: [u8; 32],
    message_limbs: [u128; P256_LIMBS],
    pub_key_x_limbs: [u128; P256_LIMBS],
    pub_key_y_limbs: [u128; P256_LIMBS],
    signature_r_limbs: [u128; P256_LIMBS],
    signature_s_limbs: [u128; P256_LIMBS],
    r_point_y_limbs: [u128; P256_LIMBS],
    s_g_limbs: [u128; P256_LIMBS],
    s_g_slices: [u8; P256_SCALAR_SLICES],
    s_g_skew: bool,
    s_g_borrow_low: bool,
    s_g_borrow_mid: bool,
    s_p_limbs: [u128; P256_LIMBS],
    s_p_slices: [u8; P256_SCALAR_SLICES],
    s_p_skew: bool,
    s_p_borrow_low: bool,
    s_p_borrow_mid: bool,
) {
    assert_be_bytes_match_limbs(signed_message_digest, message_limbs);
    assert_be_bytes_match_limbs(pub_key_x, pub_key_x_limbs);
    assert_be_bytes_match_limbs(pub_key_y, pub_key_y_limbs);
    assert_be_bytes_match_limbs(r_point_y, r_point_y_limbs);

    let gen = Secp256r1::one();
    let public = Secp256r1 {
        x: Secp256r1_Fq::from_limbs(pub_key_x_limbs),
        y: Secp256r1_Fq::from_limbs(pub_key_y_limbs),
        is_infinity: false,
    };
    public.validate_on_curve();
    let message = Secp256r1_Fr::from_limbs(message_limbs);

    let mut r: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut s: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    for i in 0..32 {
        r[i] = signature[i];
        s[i] = signature[i + 32];
    }

    assert_be_bytes_match_limbs(r, signature_r_limbs);
    assert_be_bytes_match_limbs(s, signature_s_limbs);
    let r = Secp256r1_Fr::from_limbs(signature_r_limbs);
    let s = Secp256r1_Fr::from_limbs(signature_s_limbs);
    r.validate_in_field();
    s.validate_in_field();
    r.assert_is_not_equal(Secp256r1_Fr::zero());
    s.assert_is_not_equal(Secp256r1_Fr::zero());

    let s_g_quotient = Secp256r1_Fr::from_limbs(s_g_limbs);
    let s_p_quotient = Secp256r1_Fr::from_limbs(s_p_limbs);
    assert(s_g_quotient * s == message);
    assert(s_p_quotient * s == r);
    let s_g = Secp256r1Scalar::from_slices_unchecked(s_g_slices, s_g_skew);
    let s_p = Secp256r1Scalar::from_slices_unchecked(s_p_slices, s_p_skew);
    assert_scalar_matches_bignum(s_g, s_g_quotient, s_g_skew, s_g_borrow_low, s_g_borrow_mid);
    assert_scalar_matches_bignum(s_p, s_p_quotient, s_p_skew, s_p_borrow_low, s_p_borrow_mid);
    let r_point = Secp256r1::evaluate_linear_expression([gen, public], [s_g, s_p], []);

    let mut r_point_x = Secp256r1_Fr::zero();
    for i in 0..Secp256r1_Fr::num_limbs(Secp256r1_Fr::zero()) {
        r_point_x.set_limb(i, r_point.x.get_limb(i));
    }

    assert(!r_point.is_infinity);
    assert(r_point_x == r);
    assert(r_point.y == Secp256r1_Fq::from_limbs(r_point_y_limbs));
}

fn assert_be_bytes_match_limbs(bytes: [u8; 32], limbs: [u128; P256_LIMBS]) {
    let mut high: Field = 0;
    for i in 0..2 {
        high = high * 256 + (bytes[i] as Field);
    }
    let mut mid: Field = 0;
    for i in 2..17 {
        mid = mid * 256 + (bytes[i] as Field);
    }
    let mut low: Field = 0;
    for i in 17..32 {
        low = low * 256 + (bytes[i] as Field);
    }

    assert((limbs[2] as Field) == high);
    assert((limbs[1] as Field) == mid);
    assert((limbs[0] as Field) == low);
}

fn field_limbs_to_u128(limbs: [Field; P256_LIMBS]) -> [u128; P256_LIMBS] {
    let mut result: [u128; P256_LIMBS] = [0, 0, 0];
    for i in 0..P256_LIMBS {
        limbs[i].assert_max_bit_size::<120>();
        result[i] = limbs[i] as u128;
    }
    result
}

fn assert_scalar_matches_bignum(
    scalar: Secp256r1Scalar,
    value: Secp256r1_Fr,
    skew: bool,
    borrow_low: bool,
    borrow_mid: bool,
) {
    let mut count: u32 = 0;
    let mut high: Field = 0;
    for _ in 0..5 {
        high = high * 16 + (scalar.get(count) as Field) * 2 - 15;
        count += 1;
    }

    let mut mid: Field = 0;
    for _ in 0..30 {
        mid = mid * 16 + (scalar.get(count) as Field) * 2 - 15;
        count += 1;
    }

    let mut low: Field = 0;
    for _ in 0..30 {
        low = low * 16 + (scalar.get(count) as Field) * 2 - 15;
        count += 1;
    }

    assert((value.get_limb(2) as Field) + (borrow_mid as Field) == high);
    assert(
        (value.get_limb(1) as Field) + (borrow_low as Field)
            == mid + (borrow_mid as Field) * TWO_POW_120_FIELD,
    );
    assert(
        (value.get_limb(0) as Field) + (skew as Field)
            == low + (borrow_low as Field) * TWO_POW_120_FIELD,
    );
}
