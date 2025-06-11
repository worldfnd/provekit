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
use data_check_integrity::check_integrity_of_data_sha256;

// --- Needed to check the DSC signature over the signed data ---
use data_check_tbs_pubkey::verify_rsa_pubkey_in_tbs;

// --- Needed to check the CSCA signature over the DSC pubkey ---
use sig_check_rsa::verify_signature;

fn main(
    // ------------- DSC pubkey verification against H(SOD) + "stuff" -------------
    dg1: [u8; 95],
    current_date: pub str<8>,
    min_age_required: pub u8,
    // // The maximum age required is public so verifiers can check
    // // the age provided to the proof is correct
    // // If the maximum age is 0, it is not checked
    max_age_required: pub u8,
    // This is the thing which is actually signed by the DSC
    passport_signed_attributes: [u8; 200],
    passport_signed_attributes_size: u64,
    // This is the SOD, i.e. the concatenation of the hashes of all the DGs
    // The hash of `e_content` should be contained within `signed_attributes`
    passport_sod: [u8; 700],
    passport_sod_size: u32,
    // This is just the offset within the SOD string where the DG1 hash is supposed to live.
    // TODO(ryancao): Is this not supposed to be public???
    dg1_hash_offset_in_sod: u32,
    // ------------- DSC pubkey verification against H(SOD) + "stuff" -------------
    dsc_pubkey: [u8; 256],
    dsc_barrett_mu: [u8; 257],
    passport_signed_attributes_signature: [u8; 256],
    dsc_pubkey_offset_in_dsc_cert: u32,
    dsc_rsa_exponent: u32,
    // ------------- CSC pubkey verification against DSC -------------
    // This is the DSC certificate, i.e. the cert which contains the DSC within.
    dsc_cert: [u8; 700],
    dsc_cert_len: u64,
    // This is the country signing certificate's associated public key
    csc_pubkey: [u8; 256],
    csc_barrett_mu: [u8; 257],
    // The signature for the DSC (i.e. that which is to be verified against the CSC pubkey)
    dsc_cert_signature: [u8; 256],
    csc_rsa_exponent: u32,
) {
    // Verify the age of the ID holder
    compare_age(
        dg1,
        min_age_required,
        max_age_required,
        current_date.as_bytes(),
    );

    // // Check the ID is not expired first
    check_expiry(dg1, current_date.as_bytes());
    // Check the integrity of the data
    check_integrity_of_data_sha256(
        dg1,
        passport_signed_attributes,
        passport_signed_attributes_size as u32,
        passport_sod,
        passport_sod_size,
        dg1_hash_offset_in_sod,
    );

    // --- DSC signature check ---
    // The first thing checks that the appropriate substring of the `tbs_certificate` is equivalent to the `dsc_pubkey`
    verify_rsa_pubkey_in_tbs(dsc_pubkey, dsc_cert, dsc_pubkey_offset_in_dsc_cert);
    // The second thing asserts verify_sign(message=signed_attributes, sign=sod_signature, pubkey=dsc_pubkey)
    assert(verify_signature::<256, 0, 200, 32>(
        dsc_pubkey,
        passport_signed_attributes_signature, // Technically this is the signature of `data_to_sign` and not strictly the SOD
        dsc_barrett_mu,
        dsc_rsa_exponent,
        passport_signed_attributes,
        passport_signed_attributes_size,
    ));

    // Check the signature over the DSC
    // Uses SHA-256 with a message size of 700 and a prime of 2048 bits,
    // using PKCS rather than PSS.
    assert(verify_signature::<256, 0, 700, 32>(
        csc_pubkey, // This is the pubkey to verify against
        dsc_cert_signature, // This is the actual signature
        csc_barrett_mu,
        csc_rsa_exponent,
        dsc_cert, // This is `data_to_sign`, i.e. the message
        dsc_cert_len,
    ));
}
