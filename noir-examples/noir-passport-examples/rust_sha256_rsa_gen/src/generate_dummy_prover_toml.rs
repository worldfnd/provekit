use {
    crate::{
        rsa_stuff::generate_rsa_signature_pkcs_from_priv_key,
        zkpassport_constants::{
            CSC_PUBKEY, CSC_PUBKEY_MU, DSC_CERT, DSC_CERT_SIGNATURE_BYTES, DSC_MU_BYTES,
            DSC_P_BYTES, DSC_Q_BYTES, DSC_RSA_PUBKEY_BYTES, PASSPORT_SIGNED_ATTRIBUTES_SIZE,
            PASSPORT_SOD_SIZE,
        },
    },
    std::iter::repeat_n,
};

/// Assuming here that we use all the RSA keys from `zkpassport_constants`
pub fn generate_dummy_prover_toml_string_with_data(
    dg1_bytes: &[u8; 95],
    passport_sod: &[u8; 700],
    passport_signed_attributes: &[u8; 200],
    passport_signed_attributes_signature_bytes: &[u8; 256],
) -> String {
    let mut prover_toml_str = String::new();

    // --- Purely passport DG1/SOD stuff ---
    prover_toml_str += &format!("passport_sod = {:?}\n\n", passport_sod);
    prover_toml_str += &format!("passport_sod_size = {:?}\n\n", PASSPORT_SOD_SIZE);
    prover_toml_str += &format!("dg1_hash_offset_in_sod = {:?}\n\n", 0);
    prover_toml_str += &format!("dg1 = {:?}\n\n", dg1_bytes);

    // --- DSC signature over signed attributes stuff ---
    prover_toml_str += &format!(
        "passport_signed_attributes = {:?}\n\n",
        passport_signed_attributes
    );
    prover_toml_str += &format!(
        "passport_signed_attributes_size = {:?}\n\n",
        PASSPORT_SIGNED_ATTRIBUTES_SIZE,
    );

    prover_toml_str += &format!("dsc_pubkey = {:?}\n\n", DSC_RSA_PUBKEY_BYTES);
    prover_toml_str += &format!("dsc_barrett_mu = {:?}\n\n", DSC_MU_BYTES);

    prover_toml_str += &format!(
        "passport_signed_attributes_signature = {:?}\n\n",
        passport_signed_attributes_signature_bytes
    );
    prover_toml_str += &format!("dsc_rsa_exponent = {:?}\n\n", 65537);

    // --- CSC signature over DSC cert stuff ---
    prover_toml_str += &format!("dsc_pubkey_offset_in_dsc_cert = {:?}\n\n", 0);
    prover_toml_str += &format!("dsc_cert = {:?}\n\n", DSC_CERT);
    prover_toml_str += &format!("dsc_cert_len = {:?}\n\n", 256);
    prover_toml_str += &format!("csc_pubkey = {:?}\n\n", CSC_PUBKEY);
    prover_toml_str += &format!("csc_barrett_mu = {:?}\n\n", CSC_PUBKEY_MU);
    prover_toml_str += &format!("dsc_cert_signature = {:?}\n\n", DSC_CERT_SIGNATURE_BYTES);
    prover_toml_str += &format!("csc_rsa_exponent = {:?}\n\n", 65537);

    prover_toml_str
}

/// Note: both `birthdate_bytes` and `expiry_bytes` are in the form "YYMMDD".
pub fn dg1_bytes_with_birthdate_expiry_date(
    birthdate_bytes: &[u8; 6],
    expiry_bytes: &[u8; 6],
) -> [u8; 95] {
    let mut dg1_bytes = [1; 95];

    // From Noir (we should double-check this with an actual passport):
    // MRZ offset within DG1 is 5
    // Birthdate offset within MRZ is 57, with 6 bytes allocated
    dg1_bytes[57 + 5..57 + 5 + 6].copy_from_slice(birthdate_bytes);

    // Expiry offset within MRZ is 65, with 6 bytes allocated
    dg1_bytes[65 + 5..65 + 5 + 6].copy_from_slice(expiry_bytes);

    // Set final two bytes to be zero
    dg1_bytes[93..].copy_from_slice(&[0, 0]);

    dg1_bytes
}

/// Note: `current_date` format should be "YYYYMMDD"
pub fn generate_prover_toml_string_from_custom_dg1_date_and_required_age(
    custom_dg1_bytes: &[u8; 95],
    min_age_required: u8,
    max_age_required: u8,
    current_date: &str,
) -> String {
    use sha2::{Digest, Sha256};

    // Next, compute SHA-256 digest of this
    let sha256_digest = Sha256::digest(custom_dg1_bytes);

    let passport_sod: Vec<u8> = sha256_digest
        .into_iter()
        .chain(repeat_n(0, 700 - 32))
        .collect();

    let passport_sod_hash = Sha256::digest(&passport_sod);
    let passport_signed_attributes: Vec<u8> = passport_sod_hash
        .into_iter()
        .chain(repeat_n(0, 200 - 32))
        .collect();

    // Next, generate signature of the signed attributes
    let passport_signed_attributes_signature_bytes = generate_rsa_signature_pkcs_from_priv_key(
        &DSC_P_BYTES,
        &DSC_Q_BYTES,
        &passport_signed_attributes,
    );

    // The DSC_CERT and everything afterwards should be deterministic, since
    // we are not changing the DSC_KEY.
    let mut prover_toml_str = generate_dummy_prover_toml_string_with_data(
        custom_dg1_bytes,
        &passport_sod.try_into().unwrap(),
        &passport_signed_attributes.try_into().unwrap(),
        &passport_signed_attributes_signature_bytes
            .try_into()
            .unwrap(),
    );

    prover_toml_str += &format!("min_age_required = {:?}\n\n", min_age_required);
    prover_toml_str += &format!("max_age_required = {:?}\n\n", max_age_required);
    prover_toml_str += &format!("current_date = {:?}\n\n", current_date);

    prover_toml_str
}
