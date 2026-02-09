use bignum::{params::BigNumParams, RuntimeBigNum};
use rsa::rsa::verify_sha256_pkcs1v15;

// Part 2 RSA verification - takes pre-computed hash (used in fragmented circuits)
// Note: This function only supports SHA-256 with PKCS#1 v1.5 padding
pub fn verify_rsa_signature<let SIG_BYTES: u32>(
    pubkey_bytes: [u8; SIG_BYTES],
    sig_bytes: [u8; (((SIG_BYTES * 8) + 7) / 8)],
    redc_param_bytes: [u8; SIG_BYTES + 1],
    exponent: u32,
    msg_hash: [u8; 32]  // Pre-computed SHA256 hash
) -> bool {
    assert(
        (SIG_BYTES == 768)
            | (SIG_BYTES == 512)
            | (SIG_BYTES == 384)
            | (SIG_BYTES == 256)
            | (SIG_BYTES == 128),
        "Only modulus of bit size 1024, 2048, 3072, 4096 and 6144 are supported",
    );

    let pubkey =
        utils::pack_be_bytes_into_u128s::<SIG_BYTES, (SIG_BYTES + 14) / 15, 15>(pubkey_bytes);
    let redc_param = utils::pack_be_bytes_into_u128s::<SIG_BYTES + 1, _, 15>(redc_param_bytes);
    let params = BigNumParams::new(false, pubkey, redc_param);

    let signature = RuntimeBigNum::from_be_bytes(params, sig_bytes);
    verify_sha256_pkcs1v15::<_, SIG_BYTES * 8>(msg_hash, signature, exponent)
}
