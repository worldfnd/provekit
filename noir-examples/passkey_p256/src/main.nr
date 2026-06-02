use bignum::BigNum;
use bigcurve::{
    BigCurve,
    curves::secp256r1::{Secp256r1, Secp256r1_Fq, Secp256r1_Fr, Secp256r1Scalar},
};
use sha256::sha256_var;

global AUTHENTICATOR_DATA_LEN: u32 = 37;
global CLIENT_DATA_HASH_LEN: u32 = 32;
global WEBAUTHN_SIGNED_MESSAGE_LEN: u32 = 69;

fn main(
    authenticator_data: pub [u8; AUTHENTICATOR_DATA_LEN],
    client_data_json_hash: pub [u8; CLIENT_DATA_HASH_LEN],
    pub_key_x: pub [u8; 32],
    pub_key_y: pub [u8; 32],
    signature: pub [u8; 64],
    r_point_y: [u8; 32],
) {
    let mut signed_message: [u8; WEBAUTHN_SIGNED_MESSAGE_LEN] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    for i in 0..AUTHENTICATOR_DATA_LEN {
        signed_message[i] = authenticator_data[i];
    }
    for i in 0..CLIENT_DATA_HASH_LEN {
        signed_message[AUTHENTICATOR_DATA_LEN + i] = client_data_json_hash[i];
    }

    let hashed_message = sha256_var(signed_message, WEBAUTHN_SIGNED_MESSAGE_LEN);

    verify_p256_signature(hashed_message, pub_key_x, pub_key_y, signature, r_point_y);
}

fn verify_p256_signature(
    hashed_message: [u8; 32],
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    r_point_y: [u8; 32],
) {
    let gen = Secp256r1::one();
    let public = Secp256r1 {
        x: Secp256r1_Fq::from_be_bytes(pub_key_x),
        y: Secp256r1_Fq::from_be_bytes(pub_key_y),
        is_infinity: false,
    };
    public.validate_on_curve();
    let message = Secp256r1_Fr::from_be_bytes(hashed_message);

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

    let r_x = Secp256r1_Fq::from_be_bytes(r);
    let r = Secp256r1_Fr::from_be_bytes(r);
    let s = Secp256r1_Fr::from_be_bytes(s);

    let s_g = Secp256r1Scalar::from_bignum(message / s);
    let s_p = Secp256r1Scalar::from_bignum(r / s);
    let r_point = Secp256r1::evaluate_linear_expression([gen, public], [s_g, s_p], []);

    assert(!r_point.is_infinity);
    assert(r_point.x == r_x);
    assert(r_point.y == Secp256r1_Fq::from_be_bytes(r_point_y));
}
