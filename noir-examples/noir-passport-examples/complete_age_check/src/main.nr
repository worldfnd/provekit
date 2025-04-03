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
use commitment::check_csc_certificate_exists_within_registry;
use sig_check_rsa::verify_signature;

fn main(
    // ------------- DSC pubkey verification against H(SOD) + "stuff" -------------
    dg1: [u8; 95],
    current_date: pub str<8>,
    min_age_required: pub u8,
    // The maximum age required is public so verifiers can check
    // the age provided to the proof is correct
    // If the maximum age is 0, it is not checked
    max_age_required: pub u8,
    // This is the thing which is actually signed by the DSC
    signed_attributes: [u8; 200],
    signed_attributes_size: u64,
    // This is the SOD, i.e. the concatenation of the hashes of all the DGs
    e_content: [u8; 700],
    e_content_size: u32,
    // This is just the offset within the SOD string where the DG1 hash is supposed to live.
    // TODO(ryancao): Is this not supposed to be public???
    dg1_offset_in_e_content: u32,
    // ------------- DSC pubkey verification against H(SOD) + "stuff" -------------
    dsc_pubkey: [u8; 256],
    dsc_pubkey_redc_param: [u8; 257],
    sod_signature: [u8; 256],
    pubkey_offset_in_tbs: u32,
    dsc_exponent: u32,
    // ------------- CSC pubkey verification against DSC -------------
    // There is an assumed CSC registry. In particular, it should be a Merkle
    // tree where the leaves are (registry_id, cert_type, country, csc_pubkey) tuples.
    certificate_registry_root: pub Field,
    certificate_registry_index: Field, // This is helpful for the Merkle proof for some reason
    certificate_registry_hash_path: [Field; 14],
    certificate_registry_id: Field,
    // This is the DSC certificate. I have no idea why it's called the TBS
    tbs_certificate: [u8; 700],
    tbs_certificate_len: u64,
    // This is the country signing certificate's associated public key
    csc_pubkey: [u8; 256],
    csc_pubkey_redc_param: [u8; 257],
    // The signature for the DSC (i.e. that which is to be verified against the CSC pubkey)
    dsc_signature: [u8; 256],
    csc_exponent: u32,
    country: str<3>,
) {
    // Verify the age of the ID holder
    compare_age(
        dg1,
        min_age_required,
        max_age_required,
        current_date.as_bytes(),
    );

    // Check the ID is not expired first
    check_expiry(dg1, current_date.as_bytes());
    // Check the integrity of the data
    check_integrity_of_data_sha256(
        dg1,
        signed_attributes,
        signed_attributes_size,
        e_content,
        e_content_size,
        dg1_offset_in_e_content,
    );

    // --- DSC signature check ---
    // The first thing checks that the appropriate substring of the `tbs_certificate` is equivalent to the `dsc_pubkey`
    verify_rsa_pubkey_in_tbs(dsc_pubkey, tbs_certificate, pubkey_offset_in_tbs);
    // The second thing asserts verify_sign(message=signed_attributes, sign=sod_signature, pubkey=dsc_pubkey)
    assert(verify_signature::<256, 0, 200, 32>(
        dsc_pubkey,
        sod_signature, // Technically this is the signature of `data_to_sign` and not strictly the SOD
        dsc_pubkey_redc_param,
        dsc_exponent,
        signed_attributes, // This is `data_to_sign`
        signed_attributes_size,
    ));

    // Check the signature over the DSC
    // Uses SHA-256 with a message size of 700 and a prime of 2048 bits,
    // using PKCS rather than PSS.
    assert(verify_signature::<256, 0, 700, 32>(
        csc_pubkey, // This is the pubkey to verify against
        dsc_signature, // This is the actual signature
        csc_pubkey_redc_param,
        csc_exponent,
        tbs_certificate, // This is `data_to_sign`, i.e. the message
        tbs_certificate_len,
    ));
    // Check that the CSC pubkey belongs in the registry.
    check_csc_certificate_exists_within_registry(
        certificate_registry_root,
        certificate_registry_index,
        certificate_registry_hash_path,
        certificate_registry_id,
        country,
        csc_pubkey,
    );
}
