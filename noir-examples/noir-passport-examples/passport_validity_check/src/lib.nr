// --- Needed to check the DSC signature over the signed data ---
use data_check_tbs_pubkey::verify_rsa_pubkey_in_tbs;

// --- Needed to check the CSCA signature over the DSC pubkey ---
use sig_check_rsa::verify_signature;
use utils::check_zero_padding;

// CONSTANTS
global SIGNED_ATTRIBUTES_MAX_SIZE: u32 = 200;
global DSC_CERT_MAX_SIZE: u32 = 1500;
global DSC_SIGNATURE_SIZE: u32 = 256;
global CSC_PUBKEY_SIZE: u32 = 512;

/// Contains everything necessarily for checking the validity of a passport's
/// contents against its own SOD, SOD certificate, and DSC certificate against
/// an externally supplied CSC and an externally supplied DG{k} (e.g. DG1).
/// Holds all data needed to check SOD -> DSC -> CSC validity.
pub struct PassportValidityContents {
    /// Signed Attributes block from SOD.
    pub signed_attributes: [u8; SIGNED_ATTRIBUTES_MAX_SIZE],
    /// Length of Signed Attributes.
    pub signed_attributes_size: u64,
    /// DSC signature over Signed Attributes.
    pub dsc_signature: [u8; DSC_SIGNATURE_SIZE],

    /// DSC public exponent (usually 65537).
    pub dsc_rsa_exponent: u32,
    /// DSC public key modulus (2048-bit).
    pub dsc_pubkey: [u8; DSC_SIGNATURE_SIZE],
    /// Barrett reduction param for DSC.
    pub dsc_barrett_mu: [u8; DSC_SIGNATURE_SIZE + 1],

    /// Offset of DSC pubkey inside DSC cert.
    pub dsc_pubkey_offset_in_dsc_cert: u32,
    /// Raw DSC certificate bytes.
    pub dsc_cert: [u8; DSC_CERT_MAX_SIZE],
    /// Length of DSC certificate.
    pub dsc_cert_len: u32,

    /// CSC public key modulus (4096-bit).
    pub csc_pubkey: [u8; CSC_PUBKEY_SIZE],
    /// Barrett reduction param for CSC.
    pub csc_barrett_mu: [u8; CSC_PUBKEY_SIZE + 1],
    /// CSC signature over DSC cert.
    pub dsc_cert_signature: [u8; CSC_PUBKEY_SIZE],
    /// CSC public exponent.
    pub csc_rsa_exponent: u32,

    /// eContent from SOD (hashes of DGs).
    pub econtent: [u8; SIGNED_ATTRIBUTES_MAX_SIZE],
    /// Length of eContent.
    pub econtent_len: u32,
    /// Offset of DG1 hash in eContent.
    pub dg1_hash_offset: u32,
    /// Offset of eContent hash in Signed Attributes.
    pub econtent_hash_offset: u32,
}

/// This function checks the following:
/// * H(SOD) is located correctly within the SOD certificate.
/// * The signature over the SOD certificate verifies against the DSC pubkey.
/// * The DSC pubkey is located correctly within the DSC certificate.
/// * The signature over the DSC certificate verifies against the CSC pubkey.
pub fn check_passport_validity(passport_validity_contents: PassportValidityContents) {
    // Checks that H(SOD) is located correctly within the Signed Attributes certificate.
    check_integrity_of_sod_within_sod_cert(
        passport_validity_contents.signed_attributes,
        passport_validity_contents.signed_attributes_size as u32,
        passport_validity_contents.econtent,
        passport_validity_contents.econtent_len,
        passport_validity_contents.econtent_hash_offset,
    );

    // --- SOD certificate signature check ---
    // The second thing asserts verify_sign(message=signed_attributes, sign=sod_signature, pubkey=dsc_pubkey)
    assert(verify_signature::<DSC_SIGNATURE_SIZE, 0, SIGNED_ATTRIBUTES_MAX_SIZE, 32>(
        passport_validity_contents.dsc_pubkey,
        passport_validity_contents.dsc_signature,
        passport_validity_contents.dsc_barrett_mu,
        passport_validity_contents.dsc_rsa_exponent,
        passport_validity_contents.signed_attributes,
        passport_validity_contents.signed_attributes_size as u32,
    ));

    // --- DSC certificate signature check ---
    // The first thing checks that the appropriate substring of the `tbs_certificate` is equivalent to the `dsc_pubkey`
    verify_rsa_pubkey_in_tbs(
        passport_validity_contents.dsc_pubkey,
        passport_validity_contents.dsc_cert,
        passport_validity_contents.dsc_pubkey_offset_in_dsc_cert,
    );

    // Check the signature over the DSC
    // Uses SHA-256 with a message size of 1500 and a prime of 2048 bits,
    // using PKCS rather than PSS.
    assert(verify_signature::<CSC_PUBKEY_SIZE, 0, DSC_CERT_MAX_SIZE, 32>(
        passport_validity_contents.csc_pubkey, // This is the pubkey to verify against
        passport_validity_contents.dsc_cert_signature, // This is the actual signature
        passport_validity_contents.csc_barrett_mu,
        passport_validity_contents.csc_rsa_exponent,
        passport_validity_contents.dsc_cert, // This is `data_to_sign`, i.e. the message
        passport_validity_contents.dsc_cert_len,
    ));
}

/// Exactly what the function says. Checks that the last 32 bytes within the
/// `sod_cert` match the SHA-256 hash of the `passport_sod`.
pub fn check_integrity_of_sod_within_sod_cert(
    signed_attributes: [u8; 200],
    signed_attributes_size: u32,
    econtent: [u8; 200],
    econtent_len: u32,
    econtent_hash_offset: u32,
) {
    // Check zero padding for signed_attributes
    check_zero_padding(signed_attributes, signed_attributes_size);

    // Clearly the SOD itself is supposed to be hashed and then concatenated with some other "stuff"
    // That "stuff" is the thing which is actually signed
    let econtent_hash =
        noir_native_sha256::ryan_sha256_noir::sha256_var(econtent, econtent_len as u64);

    for i in 0..32 {
        assert(econtent_hash[i] == signed_attributes[econtent_hash_offset + i]);
    }
}

/// Checks that H(DG1) exists as a substring of the correct offset within
/// the passport's SOD.
pub fn check_dg1_hash_within_sod(
    dg1: [u8; 95],
    dg1_padded_length: u64,
    econtent: [u8; 200],
    econtent_len: u32,
    dg1_hash_offset: u32,
) {
    // Check zero padding for econtent
    check_zero_padding(econtent, econtent_len);

    let dg1_hash = noir_native_sha256::ryan_sha256_noir::sha256_var(dg1, dg1_padded_length);

    // The DG1 hash is located at the start of the SOD
    // (offset is always 0 for DG1)
    for i in 0..32 {
        assert(dg1_hash[i] == econtent[dg1_hash_offset + i]);
    }
}
