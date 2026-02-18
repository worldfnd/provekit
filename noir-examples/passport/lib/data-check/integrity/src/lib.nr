use sha1::sha1;
use sha256::{sha224_var, sha256_var};
use sha512::{sha384, sha512};
use utils::{
    check_zero_padding,
    constants::{ID_CARD_DG1_LENGTH, PASSPORT_DG1_LENGTH},
    find_subarray_index,
    get_array_slice,
    is_id_card,
    is_subarray_in_array,
    types::{DG1Data, EContentData},
};

pub mod tests;

// The DER sequence preceding the hash of DG2
// the following byte being the size of the hash
pub global DG2_HASH_DER_IDENTIFIER: [u8; 4] = [0x02, 0x01, 0x02, 0x04];

/**
* Gets the hash of DG2 from eContent by using the expected DER sequence preceding it
*/
pub fn get_dg2_hash_from_econtent<let HASH_SIZE: u32>(
    e_content: EContentData,
    e_content_size: u32,
) -> [u8; HASH_SIZE] {
    let dg2_hash_der_identifier_offset = find_subarray_index(DG2_HASH_DER_IDENTIFIER, e_content);
    assert(dg2_hash_der_identifier_offset != e_content.len(), "DG2 hash not found in eContent");

    assert_eq(
        e_content[dg2_hash_der_identifier_offset - 2],
        0x30,
        "Unexpected value preceding DG2 hash",
    );
    // 5 stands for the 4 elements of DG2_HASH_DER_IDENTIFIER plus the size of the hash
    assert_eq(
        e_content[dg2_hash_der_identifier_offset - 1],
        5 + HASH_SIZE as u8,
        "DG2 hash size is not the expected size",
    );

    let dg2_hash_size_offset = dg2_hash_der_identifier_offset + DG2_HASH_DER_IDENTIFIER.len();
    let dg2_hash_size = e_content[dg2_hash_size_offset];
    // We make sure the size of the hash is the expected size
    assert_eq(dg2_hash_size, (HASH_SIZE as u8), "DG2 hash size is not the expected size");

    let dg2_hash_offset_in_e_content = dg2_hash_size_offset + 1;
    // We make sure the hash is within the expected bounds of eContent
    assert(
        dg2_hash_offset_in_e_content + HASH_SIZE <= e_content_size,
        "DG2 hash not found in eContent",
    );

    // Finally we get the hash of DG2 and return it
    let dg2_hash: [u8; HASH_SIZE] = get_array_slice(e_content, dg2_hash_offset_in_e_content);
    dg2_hash
}

pub fn get_dg1_size(dg1: DG1Data) -> u32 {
    if is_id_card(dg1) {
        ID_CARD_DG1_LENGTH
    } else {
        PASSPORT_DG1_LENGTH
    }
}

/**
* Computes the hash (using SHA1) of the first data group (containing the MRZ) and checks it is the same as the one
* included in eContent at the offset provided (along with the rest of the data group hashes)
*/
pub fn check_dg1_sha1(dg1: DG1Data, e_content: EContentData, e_content_size: u32) {
    check_zero_padding(e_content, e_content_size);

    // For passports we ignore the last padding characters
    let dg1_size: u32 = get_dg1_size(dg1);

    let dg1_bounded_vec = BoundedVec::from_parts(dg1, dg1_size);
    // We only need to recompute the hash of the MRZ (or more accurately that of Data Group 1)
    // within the circuit as this is the only data group we use to build the proof (age, country, etc.)
    let dg1_hash = sha1::sha1_var(dg1_bounded_vec);

    // Find the offset of the hash of dg1 in e_content
    let dg1_offset_in_e_content = find_subarray_index(dg1_hash, e_content);
    // Check that the hash of dg1 is in the e_content, we use the actual size rather than generic size
    // of econtent to ignore the padding bytes at the end
    assert(
        dg1_offset_in_e_content + dg1_hash.len() <= e_content_size,
        "Hash of dg1 not found in eContent",
    );
}

/**
* Computes the hash (using SHA1) of eContent (containing the hashes of the data groups) and checks it is the same as the one
* included in the signed_attributes, which is the message signed by the Document Signing Certificate (DSC)
*/
pub fn check_signed_attributes_sha1<let SA_SIZE: u32>(
    signed_attributes: [u8; SA_SIZE],
    e_content: EContentData,
    e_content_size: u32,
) {
    let e_content_bounded_vec = BoundedVec::from_parts(e_content, e_content_size);

    let computed_final_hash = sha1::sha1_var(e_content_bounded_vec);

    // Check that the computed final hash is in the signed attributes
    assert(
        is_subarray_in_array(computed_final_hash, signed_attributes),
        "Computed final hash not found in signed attributes",
    );
}

/**
* Computes the hash (using SHA2-224) of the first data group (containing the MRZ) and checks it is the same as the one
* included in eContent at the offset provided (along with the rest of the data group hashes)
*/
pub fn check_dg1_sha224(dg1: DG1Data, e_content: EContentData, e_content_size: u32) {
    check_zero_padding(e_content, e_content_size);

    // For passports we ignore the last padding characters
    let dg1_size: u64 = get_dg1_size(dg1) as u64;

    // We only need to recompute the hash of the MRZ (or more accurately that of Data Group 1)
    // within the circuit as this is the only data group we use to build the proof (age, country, etc.)
    let dg1_hash = sha224_var(dg1, dg1_size);

    // Find the offset of the hash of dg1 in e_content
    let dg1_offset_in_e_content = find_subarray_index(dg1_hash, e_content);
    // Check that the hash of dg1 is in the e_content, we use the actual size rather than generic size
    // of econtent to ignore the padding bytes at the end
    assert(
        dg1_offset_in_e_content + dg1_hash.len() <= e_content_size,
        "Hash of dg1 not found in eContent",
    );
}

/**
* Computes the hash (using SHA2-224) of eContent (containing the hashes of the data groups) and checks it is the same as the one
* included in the signed_attributes, which is the message signed by the Document Signing Certificate (DSC)
*/
pub fn check_signed_attributes_sha224<let SA_SIZE: u32>(
    signed_attributes: [u8; SA_SIZE],
    e_content: EContentData,
    e_content_size: u32,
) {
    let computed_final_hash = sha224_var(e_content, e_content_size as u64);

    // Check that the computed final hash is in the signed attributes
    assert(
        is_subarray_in_array(computed_final_hash, signed_attributes),
        "Computed final hash not found in signed attributes",
    );
}

/**
* Computes the hash (using SHA2-256) of the first data group (containing the MRZ) and checks it is the same as the one
* included in eContent at the offset provided (along with the rest of the data group hashes)
*/
pub fn check_dg1_sha256(dg1: DG1Data, e_content: EContentData, e_content_size: u32) {
    check_zero_padding(e_content, e_content_size);

    // For passports we ignore the last padding characters
    let dg1_size: u64 = get_dg1_size(dg1) as u64;

    // We only need to recompute the hash of the MRZ (or more accurately that of Data Group 1)
    // within the circuit as this is the only data group we use to build the proof (age, country, etc.)
    let dg1_hash = sha256_var(dg1, dg1_size);

    // Find the offset of the hash of dg1 in e_content
    let dg1_offset_in_e_content = find_subarray_index(dg1_hash, e_content);
    // Check that the hash of dg1 is in the e_content, we use the actual size rather than generic size
    // of econtent to ignore the padding bytes at the end
    assert(
        dg1_offset_in_e_content + dg1_hash.len() <= e_content_size,
        "Hash of dg1 not found in eContent",
    );
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

/**
* Computes the hash (using SHA2-384) of the first data group (containing the MRZ) and checks it is the same as the one
* included in eContent at the offset provided (along with the rest of the data group hashes)
*/
pub fn check_dg1_sha384(dg1: DG1Data, e_content: EContentData, e_content_size: u32) {
    check_zero_padding(e_content, e_content_size);

    // For passports we ignore the last padding characters
    let dg1_size: u32 = get_dg1_size(dg1);

    let dg1_bounded_vec = BoundedVec::from_parts(dg1, dg1_size);
    // We only need to recompute the hash of the MRZ (or more accurately that of Data Group 1)
    // within the circuit as this is the only data group we use to build the proof (age, country, etc.)
    let dg1_hash = sha384::sha384_var(dg1_bounded_vec);

    // Find the offset of the hash of dg1 in e_content
    let dg1_offset_in_e_content = find_subarray_index(dg1_hash, e_content);
    // Check that the hash of dg1 is in the e_content, we use the actual size rather than generic size
    // of econtent to ignore the padding bytes at the end
    assert(
        dg1_offset_in_e_content + dg1_hash.len() <= e_content_size,
        "Hash of dg1 not found in eContent",
    );
}

/**
* Computes the hash (using SHA2-384) of eContent (containing the hashes of the data groups) and checks it is the same as the one
* included in the signed_attributes, which is the message signed by the Document Signing Certificate (DSC)
*/
pub fn check_signed_attributes_sha384<let SA_SIZE: u32>(
    signed_attributes: [u8; SA_SIZE],
    e_content: EContentData,
    e_content_size: u32,
) {
    let e_content_bounded_vec = BoundedVec::from_parts(e_content, e_content_size);

    let computed_final_hash = sha384::sha384_var(e_content_bounded_vec);

    // Check that the computed final hash is in the signed attributes
    assert(
        is_subarray_in_array(computed_final_hash, signed_attributes),
        "Computed final hash not found in signed attributes",
    );
}

/**
* Computes the hash (using SHA2-512) of the first data group (containing the MRZ) and checks it is the same as the one
* included in eContent at the offset provided (along with the rest of the data group hashes)
*/
pub fn check_dg1_sha512(dg1: DG1Data, e_content: EContentData, e_content_size: u32) {
    check_zero_padding(e_content, e_content_size);

    // For passports we ignore the last padding characters
    let dg1_size: u32 = get_dg1_size(dg1);

    let dg1_bounded_vec = BoundedVec::from_parts(dg1, dg1_size);
    // We only need to recompute the hash of the MRZ (or more accurately that of Data Group 1)
    // within the circuit as this is the only data group we use to build the proof (age, country, etc.)
    let dg1_hash = sha512::sha512_var(dg1_bounded_vec);

    // Find the offset of the hash of dg1 in e_content
    let dg1_offset_in_e_content = find_subarray_index(dg1_hash, e_content);
    // Check that the hash of dg1 is in the e_content, we use the actual size rather than generic size
    // of econtent to ignore the padding bytes at the end
    assert(
        dg1_offset_in_e_content + dg1_hash.len() <= e_content_size,
        "Hash of dg1 not found in eContent",
    );
}

/**
* Computes the hash (using SHA2-512) of eContent (containing the hashes of the data groups) and checks it is the same as the one
* included in the signed_attributes, which is the message signed by the Document Signing Certificate (DSC)
*/
pub fn check_signed_attributes_sha512<let SA_SIZE: u32>(
    signed_attributes: [u8; SA_SIZE],
    e_content: EContentData,
    e_content_size: u32,
) {
    let e_content_bounded_vec = BoundedVec::from_parts(e_content, e_content_size);

    let computed_final_hash = sha512::sha512_var(e_content_bounded_vec);

    // Check that the computed final hash is in the signed attributes
    assert(
        is_subarray_in_array(computed_final_hash, signed_attributes),
        "Computed final hash not found in signed attributes",
    );
}
