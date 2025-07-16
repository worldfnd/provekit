// --- Needed to check the DSC signature over the signed data ---
use data_check_tbs_pubkey::verify_rsa_pubkey_in_tbs;

// --- Needed to check the CSCA signature over the DSC pubkey ---
use sig_check_rsa::verify_signature;

/// Contains everything necessarily for checking the validity of a passport's
/// contents against its own SOD, SOD certificate, and DSC certificate against
/// an externally supplied CSC and an externally supplied DG{k} (e.g. DG1).
pub struct PassportValidityContents {
    pub passport_sod: [u8; 700],
    pub passport_sod_size: u32,

    // ------------- DSC pubkey verification against H(SOD) + "stuff" -------------
    pub sod_cert: [u8; 200],
    pub sod_cert_size: u32,
    pub dsc_pubkey: [u8; 256],
    pub dsc_barrett_mu: [u8; 257],
    pub sod_cert_signature: [u8; 256],
    pub dsc_rsa_exponent: u32,

    // ------------- CSC pubkey verification against DSC -------------
    // This is the DSC certificate, i.e. the cert which contains the DSC within.
    pub dsc_pubkey_offset_in_dsc_cert: u32,
    pub dsc_cert: [u8; 700],
    pub dsc_cert_len: u32,
    // This is the country signing certificate's associated public key
    pub csc_pubkey: [u8; 256],
    pub csc_barrett_mu: [u8; 257],
    // The signature for the DSC (i.e. that which is to be verified against the CSC pubkey)
    pub dsc_cert_signature: [u8; 256],
    pub csc_rsa_exponent: u32,
}

/// This function checks the following:
/// * H(SOD) is located correctly within the SOD certificate.
/// * The signature over the SOD certificate verifies against the DSC pubkey.
/// * The DSC pubkey is located correctly within the DSC certificate.
/// * The signature over the DSC certificate verifies against the CSC pubkey.
pub fn check_passport_validity(passport_validity_contents: PassportValidityContents) {
    // Checks that H(SOD) is located correctly within the SOD certificate.
    check_integrity_of_sod_within_sod_cert(
        passport_validity_contents.passport_sod,
        passport_validity_contents.sod_cert,
        passport_validity_contents.sod_cert_size,
    );

    // --- SOD certificate signature check ---
    // The second thing asserts verify_sign(message=signed_attributes, sign=sod_signature, pubkey=dsc_pubkey)
    assert(verify_signature::<256, 0, 200, 32>(
        passport_validity_contents.dsc_pubkey,
        passport_validity_contents.sod_cert_signature,
        passport_validity_contents.dsc_barrett_mu,
        passport_validity_contents.dsc_rsa_exponent,
        passport_validity_contents.sod_cert,
        passport_validity_contents.sod_cert_size as u64,
    ));

    // --- DSC certificate signature check ---
    // The first thing checks that the appropriate substring of the `tbs_certificate` is equivalent to the `dsc_pubkey`
    verify_rsa_pubkey_in_tbs(
        passport_validity_contents.dsc_pubkey,
        passport_validity_contents.dsc_cert,
        passport_validity_contents.dsc_pubkey_offset_in_dsc_cert,
    );

    // Check the signature over the DSC
    // Uses SHA-256 with a message size of 700 and a prime of 2048 bits,
    // using PKCS rather than PSS.
    assert(verify_signature::<256, 0, 700, 32>(
        passport_validity_contents.csc_pubkey, // This is the pubkey to verify against
        passport_validity_contents.dsc_cert_signature, // This is the actual signature
        passport_validity_contents.csc_barrett_mu,
        passport_validity_contents.csc_rsa_exponent,
        passport_validity_contents.dsc_cert, // This is `data_to_sign`, i.e. the message
        passport_validity_contents.dsc_cert_len as u64,
    ));
}

/// Exactly what the function says. Checks that the last 32 bytes within the
/// `sod_cert` match the SHA-256 hash of the `passport_sod`.
pub fn check_integrity_of_sod_within_sod_cert(
    passport_sod: [u8; 700],
    sod_cert: [u8; 200],
    sod_cert_size: u32,
) {
    // Clearly the SOD itself is supposed to be hashed and then concatenated with some other "stuff"
    // That "stuff" is the thing which is actually signed
    let ryan_computed_final_hash =
        noir_native_sha256::ryan_sha256_noir::sha256_var(passport_sod, passport_sod.len() as u64); // Wrong result but passes R1CS constraints

    for i in 0..32 {
        // The last 32 bytes of the sod_cert is the hash of the SOD itself
        assert(ryan_computed_final_hash[i] == sod_cert[sod_cert_size - 32 + i]);
    }
}

/// Checks that H(DG1) exists as a substring of the correct offset within
/// the passport's SOD.
pub fn check_dg1_hash_within_sod(dg1: [u8; 95], sod: [u8; 700], dg1_offset_in_sod: u32) {
    let dg1_hash = noir_native_sha256::ryan_sha256_noir::sha256_var(dg1, dg1.len() as u64);

    for i in 0..32 {
        // Check the hash of dg1 is indeed in the sod
        assert(dg1_hash[i] == sod[dg1_offset_in_sod + i]);
    }
}
