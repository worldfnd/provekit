use sha1::sha1;
use sha256::{sha224_var, sha256_var};
use sha512::{sha384, sha512};
use utils::check_zero_padding;
use utils::types::{SHA1Digest, SHA224Digest, SHA256Digest, SHA384Digest, SHA512Digest};

pub fn sha1_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
) -> SHA1Digest {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    let data_to_sign_vec = BoundedVec::from_parts_unchecked(data_to_sign, data_to_sign_len);
    sha1::sha1_var(data_to_sign_vec)
}

pub fn sha224_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
) -> SHA224Digest {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    sha224_var(data_to_sign, data_to_sign_len as u64)
}

pub fn sha256_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
) -> SHA256Digest {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    sha256_var(data_to_sign, data_to_sign_len as u64)
}

pub fn sha384_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
) -> SHA384Digest {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    let data_to_sign_vec = BoundedVec::from_parts_unchecked(data_to_sign, data_to_sign_len);
    sha384::sha384_var(data_to_sign_vec)
}

pub fn sha512_and_check_data_to_sign<let DATA_TO_SIGN_MAX_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_MAX_LEN],
    data_to_sign_len: u32,
) -> SHA512Digest {
    // Ensure all bytes beyond data_to_sign_len are zero to prevent them
    // from being used by the prover
    check_zero_padding(data_to_sign, data_to_sign_len);
    // Calculate the hash of data_to_sign up to data_to_sign_len
    let data_to_sign_vec = BoundedVec::from_parts_unchecked(data_to_sign, data_to_sign_len);
    sha512::sha512_var(data_to_sign_vec)
}
