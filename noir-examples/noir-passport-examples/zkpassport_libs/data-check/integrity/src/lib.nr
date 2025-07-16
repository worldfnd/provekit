use utils::is_id_card;

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
    _e_content_size: u32, // TODO(ryancao): Test this against a real passport -- I think we should be using `digest()`, but unconfirmed
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
    let dg1_hash = noir_native_sha256::ryan_sha256_noir::sha256_var(dg1, dg1.len() as u64);

    for i in 0..32 {
        // Check the hash of dg1 is indeed in the e_content
        assert(dg1_hash[i] == e_content[dg1_offset_in_e_content + i]);
    }

    // --- Additionally, clearly the SOD itself is supposed to be hashed and then concatenated with some other "stuff" ---
    // --- That "stuff" is the thing which is actually signed ---
    let ryan_computed_final_hash =
        noir_native_sha256::ryan_sha256_noir::sha256_var(e_content, e_content.len() as u64);

    for i in 0..32 {
        // The last 32 bytes of the signed_attributes are the hash of the data groups
        // The rest is padding and the signature date, not important to check
        assert(ryan_computed_final_hash[i] == signed_attributes[signed_attributes_size - 32 + i]);
    }
}
