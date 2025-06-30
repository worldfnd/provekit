pub mod generate_dummy_prover_toml;
pub mod rsa_stuff;
pub mod zkpassport_constants;

use crate::generate_dummy_prover_toml::{
    dg1_bytes_with_birthdate_expiry_date,
    generate_prover_toml_string_from_custom_dg1_date_and_required_age,
};

fn main() {
    // --- RSA stuff ---
    // generate_random_rsa_params();
    // generate_rsa_signature_pkcs_from_priv_key(&CSC_P_BYTES, &CSC_Q_BYTES,
    // &DSC_CERT);

    // --- Generating dummy Noir `Prover.toml` string ---
    // First, we generate the custom DG1
    let birthdate_bytes = [b'1', b'1', b'0', b'6', b'0', b'9']; // June 9th, 2011
    let expiry_bytes = [b'3', b'0', b'0', b'8', b'2', b'5']; // August 25, 2030
    let current_date = "20250612"; // June 12, 2025
    let custom_dg1_with_birthdate_expiry =
        dg1_bytes_with_birthdate_expiry_date(&birthdate_bytes, &expiry_bytes);
    // Next, we compute all the required fields and return a custom `Prover.toml`
    // string, to be written to file.
    let prover_toml_string = generate_prover_toml_string_from_custom_dg1_date_and_required_age(
        &custom_dg1_with_birthdate_expiry,
        5,
        50,
        current_date,
    );
    println!("{prover_toml_string}");
}
