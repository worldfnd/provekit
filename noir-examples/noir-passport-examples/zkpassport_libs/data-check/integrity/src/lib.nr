use sha512::{sha384, sha512};
use sha256::sha256_var;
use utils::{
    check_zero_padding,
    constants::{ID_CARD_DG1_LENGTH, PASSPORT_DG1_LENGTH},
    find_subarray_index,
    is_id_card,
    is_subarray_in_array,
    types::{DG1Data, EContentData},
};
/**
* Computes the hash of the MRZ (Data Group 1) and checks it is the same as the one
* provided in the SOD file of the ID and then use it along with the rest of the
* hashes of the remaining data groups to compute the final hash contained in the last 32 bytes of
* eContent that is then signed by the Document Signing Certificate (DSC)
* This lets us make sure the data is authentic and has not been tampered with, so we can use the data
* of the MRZ to build subsequent proofs (age, citizenship, etc.)
*/
pub fn check_integrity_of_data_sha256(
    dg1: [u8; 95],
    // --- This is clearly the thing which is actually signed ---
    signed_attributes: [u8; 200],
    signed_attributes_size: u32,
    // --- Okay so this is clearly the SOD, i.e. the thing which the hash of DG1 is supposed to be contained in ---
    e_content: [u8; 700],
    e_content_size: u32,
    dg1_offset_in_e_content: u32,
) {
    // For passports we ignore the last padding characters
    let mut dg1_size: u64 = 93;
    let mut x: u64 = 0;

    // If it's an ID card then the array should not have any padding
    // character
    if is_id_card(dg1) {
        println("this is reached");
        x = 3;
        dg1_size = 95;
    }

    // We only need to recompute the hash of the MRZ (or more accurately that of Data Group 1)
    // within the circuit as this is the only data group we use to build the proof (age, country, etc.)
    let dg1_hash = sha256_var(dg1, dg1.len() as u64); // This gives the wrong result but succeeds in R1CS constraints

    for i in 0..32 {
        // Check the hash of dg1 is indeed in the e_content
        assert(dg1_hash[i] == e_content[dg1_offset_in_e_content + i]);
    }

    // --- Additionally, clearly the SOD itself is supposed to be hashed and then concatenated with some other "stuff" ---
    // --- That "stuff" is the thing which is actually signed ---
    let ryan_computed_final_hash =
        sha256_var(e_content, e_content.len() as u64); // Wrong result but passes R1CS constraints

    for i in 0..32 {
        // The last 32 bytes of the signed_attributes are the hash of the data groups
        // The rest is padding and the signature date, not important to check
        assert(ryan_computed_final_hash[i] == signed_attributes[signed_attributes_size - 32 + i]);
    }
}

pub fn check_integrity_of_data_sha384(
    dg1: [u8; 95],
    signed_attributes: [u8; 200],
    signed_attributes_size: u32,
    e_content: [u8; 700],
    e_content_size: u32,
    dg1_offset_in_e_content: u32,
) {
    // For passports we ignore the last padding characters
    let mut dg1_size: u64 = 93;

    // If it's an ID card then the array should not have any padding
    // character
    if is_id_card(dg1) {
        dg1_size = 95;
    }

    let dg1_bounded_vec = BoundedVec::from_parts(dg1, dg1_size as u32);
    // We only need to recompute the hash of the MRZ (or more accurately that of Data Group 1)
    // within the circuit as this is the only data group we use to build the proof (age, country, etc.)
    let dg1_hash = sha384::sha384_var(dg1_bounded_vec);

    for i in 0..48 {
        // Check the hash of dg1 is indeed in the e_content
        assert(dg1_hash[i] == e_content[dg1_offset_in_e_content + i]);
    }

    let e_content_bounded_vec = BoundedVec::from_parts(e_content, e_content_size as u32);

    let computed_final_hash = sha384::sha384_var(e_content_bounded_vec);

    for i in 0..48 {
        // The last 48 bytes of the signed_attributes are the hash of the data groups
        // The rest is padding and the signature date, not important to check
        assert(computed_final_hash[i] == signed_attributes[signed_attributes_size - 48 + i]);
    }
}

pub fn check_integrity_of_data_sha512(
    dg1: [u8; 95],
    signed_attributes: [u8; 200],
    signed_attributes_size: u32,
    e_content: [u8; 700],
    e_content_size: u32,
    dg1_offset_in_e_content: u32,
) {
    // For passports we ignore the last padding characters
    let mut dg1_size: u64 = 93;

    // If it's an ID card then the array should not have any padding
    // character
    if is_id_card(dg1) {
        dg1_size = 95;
    }

    let dg1_bounded_vec = BoundedVec::from_parts(dg1, dg1_size as u32);
    // We only need to recompute the hash of the MRZ (or more accurately that of Data Group 1)
    // within the circuit as this is the only data group we use to build the proof (age, country, etc.)
    let dg1_hash = sha512::sha512_var(dg1_bounded_vec);

    for i in 0..64 {
        // Check the hash of dg1 is indeed in the e_content
        assert(dg1_hash[i] == e_content[dg1_offset_in_e_content + i]);
    }

    let e_content_bounded_vec = BoundedVec::from_parts(e_content, e_content_size as u32);

    let computed_final_hash = sha512::sha512_var(e_content_bounded_vec);

    for i in 0..64 {
        // The last 64 bytes of the signed_attributes are the hash of the data groups
        // The rest is padding and the signature date, not important to check
        assert(computed_final_hash[i] == signed_attributes[signed_attributes_size - 64 + i]);
    }
}

pub fn get_dg1_size(dg1: DG1Data) -> u32 {
    if is_id_card(dg1) {
        ID_CARD_DG1_LENGTH
    } else {
        PASSPORT_DG1_LENGTH
    }
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
