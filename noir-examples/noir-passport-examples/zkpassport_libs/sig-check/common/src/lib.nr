use sha1::sha1;
use sha256::sha224_var;
use sha512::{sha384, sha512};
use utils::check_zero_padding;

pub fn sha1_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
) -> [u8; 20] {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    let data_to_sign_vec = BoundedVec::from_parts(data_to_sign, data_to_sign_len);

    sha1::sha1_var(data_to_sign_vec)
}

pub fn sha224_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
) -> [u8; 28] {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    sha224_var(data_to_sign, data_to_sign_len as u64)
}

pub fn sha256_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
) -> [u8; 32] {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    // sha256_var(data_to_sign, data_to_sign_len as u64)

    // Hash the entire buffer to match the signature created on the fixed-size message
    // `data_to_sign_len` is still checked above to ensure trailing bytes are zero,
    let ret =
        noir_native_sha256::ryan_sha256_noir::sha256_var(data_to_sign, data_to_sign_len as u64);

    ret
}

pub fn sha384_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
) -> [u8; 48] {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    let data_to_sign_vec = BoundedVec::from_parts(data_to_sign, data_to_sign_len);
    sha384::sha384_var(data_to_sign_vec)
}

pub fn sha512_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
) -> [u8; 64] {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    let data_to_sign_vec = BoundedVec::from_parts(data_to_sign, data_to_sign_len);
    sha512::sha512_var(data_to_sign_vec)
}
