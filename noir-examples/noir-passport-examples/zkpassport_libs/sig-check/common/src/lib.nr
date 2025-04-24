use sha256;
use sha512::{sha384, sha512};
use utils::check_zero_padding;

pub fn sha256_and_check_data_to_sign<let DATA_TO_SIGN_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_LEN],
    data_to_sign_len: u64,
) -> [u8; 32] {
    // Check that the data signed does stop at the specified length
    // to prevent the prover from using the bytes beyond that point
    // to manipulate it in their favor
    check_zero_padding(data_to_sign, data_to_sign_len as u32);

    sha256::sha256_var(data_to_sign, data_to_sign_len)
}

pub fn sha384_and_check_data_to_sign<let DATA_TO_SIGN_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_LEN],
    data_to_sign_len: u64,
) -> [u8; 48] {
    // Check that the data signed does stop at the specified length
    // to prevent the prover from using the bytes beyond that point
    // to manipulate it in their favor
    check_zero_padding(data_to_sign, data_to_sign_len as u32);

    let data_to_sign_vec = BoundedVec::from_parts(data_to_sign, data_to_sign_len as u32);
    sha384::sha384_var(data_to_sign_vec)
}

pub fn sha512_and_check_data_to_sign<let DATA_TO_SIGN_LEN: u32>(
    data_to_sign: [u8; DATA_TO_SIGN_LEN],
    data_to_sign_len: u64,
) -> [u8; 64] {
    // Check that the data signed does stop at the specified length
    // to prevent the prover from using the bytes beyond that point
    // to manipulate it in their favor
    check_zero_padding(data_to_sign, data_to_sign_len as u32);

    let data_to_sign_vec = BoundedVec::from_parts(data_to_sign, data_to_sign_len as u32);
    sha512::sha512_var(data_to_sign_vec)
}
