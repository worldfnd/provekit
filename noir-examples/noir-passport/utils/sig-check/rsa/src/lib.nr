use bignum::{params::BigNumParams, RuntimeBigNum};
use common::{
    assert_allowed_rsa_exponent, sha1_and_check_data_to_sign, sha256_and_check_data_to_sign,
    sha384_and_check_data_to_sign, sha512_and_check_data_to_sign,
};
use poseidon::poseidon2::Poseidon2;
use rsa::rsa::{
    verify_sha1_pkcs1v15, verify_sha1_pss, verify_sha256_pkcs1v15, verify_sha256_pss,
    verify_sha384_pkcs1v15, verify_sha384_pss, verify_sha512_pkcs1v15, verify_sha512_pss,
};

global RSA_KEY_NE_HASH_DOMAIN: Field = 0x5253415f4e455f48; // "RSA_NE_H"

fn exponent_to_be_bytes(exponent: u32) -> [u8; 4] {
    [
        ((exponent >> 24) & 0xFF) as u8,
        ((exponent >> 16) & 0xFF) as u8,
        ((exponent >> 8) & 0xFF) as u8,
        (exponent & 0xFF) as u8,
    ]
}

pub fn compute_key_ne_hash<let SIG_BYTES: u32>(pubkey_bytes: [u8; SIG_BYTES], exponent: u32) -> Field {
    assert_allowed_rsa_exponent(exponent);
    let exponent_bytes = exponent_to_be_bytes(exponent);
    let packed_pubkey: [Field; (SIG_BYTES + 30) / 31] =
        utils::pack_be_bytes_into_fields::<SIG_BYTES, _, 31>(pubkey_bytes);
    let packed_exponent: [Field; 1] = utils::pack_be_bytes_into_fields::<4, 1, 31>(exponent_bytes);

    let mut hash_input: [Field; 2 + (SIG_BYTES + 30) / 31] = [0; 2 + (SIG_BYTES + 30) / 31];
    hash_input[0] = RSA_KEY_NE_HASH_DOMAIN;
    for i in 0..((SIG_BYTES + 30) / 31) {
        hash_input[1 + i] = packed_pubkey[i];
    }
    hash_input[1 + ((SIG_BYTES + 30) / 31)] = packed_exponent[0];
    Poseidon2::hash(hash_input, 2 + ((SIG_BYTES + 30) / 31))
}

pub fn verify_signature<let SIG_BYTES: u32, let IS_PSS: u32, let DATA_TO_SIGN_MAX_LEN: u32, let HASH_BYTE_SIZE: u32>(
    pubkey_bytes: [u8; SIG_BYTES],
    // This is equivalent to sig_bytes: [u8; SIG_BYTES] but because of
    // an issue with the expected type for from_be_bytes we need to do it like this
    sig_bytes: [u8; (((SIG_BYTES * 8) + 7) / 8)],
    redc_param_bytes: [u8; SIG_BYTES + 1],
    exponent: u32,
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
    pss_salt_len: u32,
) -> bool {
    assert(
        (SIG_BYTES == 768)
            | (SIG_BYTES == 512)
            | (SIG_BYTES == 384)
            | (SIG_BYTES == 256)
            | (SIG_BYTES == 128),
        "Only modulus of bit size 1024, 2048, 3072, 4096 and 6144 are supported",
    );
    // TODO: Add support for more exponent values if needed for other countries. 
    assert_allowed_rsa_exponent(exponent);

    let pubkey =
        utils::pack_be_bytes_into_u128s::<SIG_BYTES, (SIG_BYTES + 14) / 15, 15>(pubkey_bytes);
    let redc_param = utils::pack_be_bytes_into_u128s::<SIG_BYTES + 1, _, 15>(redc_param_bytes);
    let params = BigNumParams::new(false, pubkey, redc_param);

    let signature = RuntimeBigNum::from_be_bytes(params, sig_bytes);

    if (IS_PSS == 1) {
        if (HASH_BYTE_SIZE == 20) {
            let msg_hash = sha1_and_check_data_to_sign(data_to_sign, data_to_sign_len);
            verify_sha1_pss::<_, SIG_BYTES * 8>(msg_hash, signature, exponent, pss_salt_len)
        } else if (HASH_BYTE_SIZE == 32) {
            let msg_hash = sha256_and_check_data_to_sign(data_to_sign, data_to_sign_len);
            verify_sha256_pss::<_, SIG_BYTES * 8>(msg_hash, signature, exponent, pss_salt_len)
        } else if (HASH_BYTE_SIZE == 48) {
            let msg_hash = sha384_and_check_data_to_sign(data_to_sign, data_to_sign_len);
            verify_sha384_pss::<_, SIG_BYTES * 8>(msg_hash, signature, exponent, pss_salt_len)
        } else if (HASH_BYTE_SIZE == 64) {
            let msg_hash = sha512_and_check_data_to_sign(data_to_sign, data_to_sign_len);
            verify_sha512_pss::<_, SIG_BYTES * 8>(msg_hash, signature, exponent, pss_salt_len)
        } else {
            false
        }
    } else {
        if (HASH_BYTE_SIZE == 20) {
            let msg_hash = sha1_and_check_data_to_sign(data_to_sign, data_to_sign_len);
            verify_sha1_pkcs1v15::<_, SIG_BYTES * 8>(msg_hash, signature, exponent)
        } else if (HASH_BYTE_SIZE == 32) {
            let msg_hash = sha256_and_check_data_to_sign(data_to_sign, data_to_sign_len);
            verify_sha256_pkcs1v15::<_, SIG_BYTES * 8>(msg_hash, signature, exponent)
        } else if (HASH_BYTE_SIZE == 48) {
            let msg_hash = sha384_and_check_data_to_sign(data_to_sign, data_to_sign_len);
            verify_sha384_pkcs1v15::<_, SIG_BYTES * 8>(msg_hash, signature, exponent)
        } else if (HASH_BYTE_SIZE == 64) {
            let msg_hash = sha512_and_check_data_to_sign(data_to_sign, data_to_sign_len);
            verify_sha512_pkcs1v15::<_, SIG_BYTES * 8>(msg_hash, signature, exponent)
        } else {
            false
        }
    }
}

#[test]
fn test_allowed_rsa_exponents() {
    assert_allowed_rsa_exponent(3);
    assert_allowed_rsa_exponent(38129);
    assert_allowed_rsa_exponent(56611);
    assert_allowed_rsa_exponent(65537);
    assert_allowed_rsa_exponent(107903);
    assert_allowed_rsa_exponent(109729);
    assert_allowed_rsa_exponent(122125);
    assert_allowed_rsa_exponent(130689);
}

#[test(should_fail_with = "Unsupported RSA exponent")]
fn test_rejects_exponent_one() {
    assert_allowed_rsa_exponent(1);
}

#[test]
fn test_compute_key_ne_hash_differs_by_exponent() {
    // Same pubkey, different exponent must produce different hash.
    // Catches regressions where the exponent is dropped from the hash input.
    let pubkey: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
    let hash_65537 = compute_key_ne_hash::<4>(pubkey, 65537);
    let hash_3 = compute_key_ne_hash::<4>(pubkey, 3);
    assert(hash_65537 != hash_3);
}

#[test]
fn test_compute_key_ne_hash_differs_by_pubkey() {
    // Same exponent, different pubkey must produce different hash.
    // Catches regressions where the pubkey is dropped from the hash input.
    let pubkey_a: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
    let pubkey_b: [u8; 4] = [0x05, 0x06, 0x07, 0x08];
    let hash_a = compute_key_ne_hash::<4>(pubkey_a, 65537);
    let hash_b = compute_key_ne_hash::<4>(pubkey_b, 65537);
    assert(hash_a != hash_b);
}
