/*
############################################################
# Ryan attempt at combining different circuit statements together
############################################################
# Should do three things:
    - Checks that the hash of DG1 exists in SOD
    - Checks that H(SOD) || other stuff is signed by DSC public key
    - Checks that the DSC is signed by the CSC public key
    - Optionally checks that the CSC itself exists within a certificate registry (committed to via Merkle tree)
############################################################

# Inputs/Outputs
    - Takes in DG1 as an untrusted private input
    - Takes in the current date as a public input
    - Takes in the SOD as an untrusted private input
    - Takes in the DSC public key as an untrusted private input
    - Takes in the CSCA public key as a public input 
        (alternatively, we can take it in as an untrusted private input with
         some Merkle proof to a CSCA pubkey tree root somewhere)
    - Optionally, takes in a CSCA Merkle proof as untrusted private input
    - Optionally, takes in a CSCA pubkey tree root as public input
############################################################
*/

// --- Needed for the `compare_age` functionality ---
use compare_age::compare_age;

// --- Needed to check DG1 integrity against SOD, as well as expiration date within DG1 ---
use data_check_expiry::check_expiry;

// --- Needed to check the CSCA signature over the DSC pubkey ---
use passport_validity_check::{
    check_dg1_hash_within_sod, check_passport_validity, PassportValidityContents,
};

fn main(
    dg1: [u8; 95],
    // This is just the offset within the SOD string where the DG1 hash is supposed to live.
    // TODO(ryancao): Is this not supposed to be public???
    dg1_hash_offset_in_sod: u32,
    current_date: pub str<8>,
    min_age_required: pub u8,
    // The maximum age required is public so verifiers can check
    // the age provided to the proof is correct
    // If the maximum age is 0, it is not checked
    max_age_required: pub u8,
    passport_validity_contents: PassportValidityContents,
) {
    // Verify the age of the ID holder
    compare_age(
        dg1,
        min_age_required,
        max_age_required,
        current_date.as_bytes(),
    );

    // Check that the ID is not expired.
    check_expiry(dg1, current_date.as_bytes());

    // Check that H(DG1) exists within the SOD.
    check_dg1_hash_within_sod(
        dg1,
        passport_validity_contents.passport_sod,
        dg1_hash_offset_in_sod,
    );

    // Performs the remainder of the passport validity checks
    // (see function documentation for details).
    check_passport_validity(passport_validity_contents);
}
