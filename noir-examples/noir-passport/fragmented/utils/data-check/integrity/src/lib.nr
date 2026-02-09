use sha256::sha256_var;
use utils::{
    check_zero_padding,
    is_subarray_in_array,
    types::EContentData,
};

pub fn check_dg1_hash_within_sod(
    dg1: [u8; 95],
    dg1_padded_length: u64,
    econtent: [u8; 200],
    econtent_len: u32,
    dg1_hash_offset: u32,
) {
    // Check zero padding for econtent
    check_zero_padding(econtent, econtent_len);

    // Bounds check: ensure dg1_hash_offset + 32 doesn't exceed econtent_len
    assert(dg1_hash_offset + 32 <= econtent_len, "dg1_hash_offset out of bounds");

    let dg1_hash = sha256_var(dg1, dg1_padded_length);

    // The DG1 hash is located at the start of the SOD
    // (offset is always 0 for DG1)
    for i in 0..32 {
        assert(dg1_hash[i] == econtent[dg1_hash_offset + i]);
    }
}
/**
* Computes the hash (using SHA2-256) of eContent (containing the hashes of the data groups) and checks it is the same as the one
* included in the signed_attributes, which is the message signed by the Document Signing Certificate (DSC)
*/
pub fn check_signed_attributes_sha256<let SA_SIZE: u32>(
    signed_attributes: [u8; SA_SIZE],
    e_content: EContentData,
    e_content_size: u32,
) {
    let computed_final_hash = sha256_var(e_content, e_content_size as u64);

    // Check that the computed final hash is in the signed attributes
    assert(
        is_subarray_in_array(computed_final_hash, signed_attributes),
        "Computed final hash not found in signed attributes",
    );
}
