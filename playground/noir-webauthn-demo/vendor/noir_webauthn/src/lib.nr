use bignum::BigNum;
use bigcurve::{
    BigCurve,
    curves::secp256r1::{Secp256r1, Secp256r1_Fq, Secp256r1_Fr, Secp256r1Scalar},
};

pub global SIGNATURE_LEN: u32 = 64;
global P256_LIMBS: u32 = 3;
global P256_SCALAR_SLICES: u32 = 65;
global TWO_POW_120_FIELD: Field = 0x1000000000000000000000000000000;

pub fn verify_signature<let CLIENT_DATA_JSON_MAX_LEN: u32, let AUTHENTICATOR_DATA_MAX_LEN: u32>(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; SIGNATURE_LEN],
    client_data_json: BoundedVec<u8, CLIENT_DATA_JSON_MAX_LEN>,
    authenticator_data: BoundedVec<u8, AUTHENTICATOR_DATA_MAX_LEN>,
    challenge: [u8; 32],
    challenge_index: u32,
    r_point_y: [u8; 32],
    message_limbs: [u128; P256_LIMBS],
    public_key_x_limbs: [u128; P256_LIMBS],
    public_key_y_limbs: [u128; P256_LIMBS],
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
        message_limbs,
        public_key_x_limbs,
        public_key_y_limbs,
        signature_r_limbs,
        signature_s_limbs,
        r_point_y_limbs,
        s_g_limbs,
        s_g_slices,
        s_g_skew,
        s_g_borrow_low,
        s_g_borrow_mid,
        s_p_limbs,
        s_p_slices,
        s_p_skew,
        s_p_borrow_low,
        s_p_borrow_mid,
    );
    true
}

fn verify_p256_signature(
    hashed_message: [u8; 32],
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; SIGNATURE_LEN],
    r_point_y: [u8; 32],
    message_limbs: [u128; P256_LIMBS],
    public_key_x_limbs: [u128; P256_LIMBS],
    public_key_y_limbs: [u128; P256_LIMBS],
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
    assert_be_bytes_match_limbs(hashed_message, message_limbs);
    assert_be_bytes_match_limbs(public_key_x, public_key_x_limbs);
    assert_be_bytes_match_limbs(public_key_y, public_key_y_limbs);
    assert_be_bytes_match_limbs(r_point_y, r_point_y_limbs);

    let gen = Secp256r1::one();
    let public = Secp256r1 {
        x: Secp256r1_Fq::from_limbs(public_key_x_limbs),
        y: Secp256r1_Fq::from_limbs(public_key_y_limbs),
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
