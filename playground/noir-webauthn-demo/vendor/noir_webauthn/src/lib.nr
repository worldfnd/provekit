use bignum::BigNum;
use bigcurve::{
    BigCurve,
    curves::secp256r1::{Secp256r1, Secp256r1_Fq, Secp256r1_Fr, Secp256r1Scalar},
};

pub global SIGNATURE_LEN: u32 = 64;

pub fn verify_signature<let CLIENT_DATA_JSON_MAX_LEN: u32, let AUTHENTICATOR_DATA_MAX_LEN: u32>(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; SIGNATURE_LEN],
    client_data_json: BoundedVec<u8, CLIENT_DATA_JSON_MAX_LEN>,
    authenticator_data: BoundedVec<u8, AUTHENTICATOR_DATA_MAX_LEN>,
    challenge: [u8; 32],
    challenge_index: u32,
    r_point_y: [u8; 32],
) -> bool {
    let client_data_json_hash = nodash::sha256(client_data_json);
    let concatenated: BoundedVec<u8, AUTHENTICATOR_DATA_MAX_LEN + 32> =
        concat(authenticator_data, client_data_json_hash);
    let hashed_message = nodash::sha256(concatenated);

    let challenge_base64_url: [u8; 43] = base64::BASE64_URL_ENCODER::encode(challenge);
    str_contains_base64_url(
        client_data_json.storage(),
        challenge_base64_url,
        challenge_index,
    );

    verify_p256_signature(
        hashed_message,
        public_key_x,
        public_key_y,
        signature,
        r_point_y,
    );
    true
}

fn verify_p256_signature(
    hashed_message: [u8; 32],
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; SIGNATURE_LEN],
    r_point_y: [u8; 32],
) {
    let gen = Secp256r1::one();
    let public = Secp256r1 {
        x: Secp256r1_Fq::from_be_bytes(public_key_x),
        y: Secp256r1_Fq::from_be_bytes(public_key_y),
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

fn str_contains_base64_url<let N: u32, let H: u32>(haystack: [u8; H], needle: [u8; N], index: u32) {
    for i in 0..needle.len() {
        if (needle[i] != 61) {
            assert(haystack[index + i] == needle[i]);
        }
    }
}

fn concat<let N: u32>(a: BoundedVec<u8, N>, b: [u8; 32]) -> BoundedVec<u8, N + 32> {
    let mut result = [0 as u8; N + 32];
    let mut j = 0;
    for i in 0..N {
        if (i < a.len()) {
            result[j] = a.get(i);
            j += 1;
        }
    }
    for i in 0..b.len() {
        result[j] = b[i];
        j += 1;
    }
    BoundedVec::from_parts(result, j)
}
