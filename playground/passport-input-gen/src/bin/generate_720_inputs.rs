/// Generate TOML input files for the 4-circuit merkle_age_check TBS-720 chain.
///
/// Uses mock passport data (RSA-4096 CSCA, RSA-2048 DSC) via generate_fake_sod
/// and the PassportReader pipeline to produce circuit inputs.
///
/// Output files:
///   - t_add_dsc_720.toml
///   - t_add_id_data_720.toml
///   - t_add_integrity_commit.toml
///   - t_attest.toml
use passport_input_gen::{
    mock_generator::{dg1_bytes_with_birthdate_expiry_date, generate_fake_sod},
    mock_keys::{MOCK_CSCA_PRIV_KEY_B64, MOCK_DSC_PRIV_KEY_B64},
    Binary, MerkleAge720Config, PassportReader,
};

use {
    base64::{engine::general_purpose::STANDARD, Engine as _},
    rsa::pkcs8::DecodePrivateKey,
    rsa::RsaPrivateKey,
    std::path::Path,
};

fn main() {
    println!("================================================================");
    println!("  merkle_age_check TBS-720 Input Generator");
    println!("  (4-circuit chain: dsc_720 -> id_data_720 -> integrity -> attest)");
    println!("================================================================\n");

    // === Step 1: Load mock RSA key pairs ===
    println!("Step 1: Load mock RSA key pairs");
    println!("------------------------------------------------------------------------");

    let csca_der = STANDARD
        .decode(MOCK_CSCA_PRIV_KEY_B64)
        .expect("Failed to decode CSCA private key");
    let csca_priv =
        RsaPrivateKey::from_pkcs8_der(&csca_der).expect("Failed to parse CSCA private key");
    let csca_pub = csca_priv.to_public_key();
    println!("  CSCA key loaded (RSA-4096)");

    let dsc_der = STANDARD
        .decode(MOCK_DSC_PRIV_KEY_B64)
        .expect("Failed to decode DSC private key");
    let dsc_priv =
        RsaPrivateKey::from_pkcs8_der(&dsc_der).expect("Failed to parse DSC private key");
    let dsc_pub = dsc_priv.to_public_key();
    println!("  DSC key loaded (RSA-2048)");
    println!();

    // === Step 2: Create mock passport data ===
    println!("Step 2: Create mock passport data");
    println!("------------------------------------------------------------------------");

    // DOB: Jan 1, 2007 (YYMMDD), Expiry: Jan 1, 2032
    let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");
    println!("  DG1: {} bytes", dg1.len());
    println!(
        "    DOB at [62..68]: \"{}\"",
        String::from_utf8_lossy(&dg1[62..68])
    );
    println!(
        "    Expiry at [70..76]: \"{}\"",
        String::from_utf8_lossy(&dg1[70..76])
    );

    let sod = generate_fake_sod(&dg1, &dsc_priv, &dsc_pub, &csca_priv, &csca_pub);
    println!("  SOD generated (fake)");
    println!();

    // === Step 3: Create PassportReader and validate ===
    println!("Step 3: Create PassportReader and validate");
    println!("------------------------------------------------------------------------");

    let reader = PassportReader::new(Binary::from_slice(&dg1), sod, true, Some(csca_pub));

    let csca_idx = reader.validate().expect("Passport validation failed");
    println!("  Validation passed (CSCA key index: {})", csca_idx);
    println!();

    // === Step 4: Configure and generate circuit inputs ===
    println!("Step 4: Generate circuit inputs");
    println!("------------------------------------------------------------------------");

    let config = MerkleAge720Config {
        current_date: 1735689600, // Jan 1, 2025 00:00:00 UTC
        min_age_required: 18,
        max_age_required: 0, // no upper bound
        ..Default::default()
    };

    let inputs = reader
        .to_merkle_age_720_inputs(csca_idx, config)
        .expect("Failed to generate circuit inputs");
    println!("  Circuit inputs generated for all 4 circuits");
    println!();

    // === Step 5: Save TOML files ===
    println!("Step 5: Save TOML files");
    println!("------------------------------------------------------------------------");

    let base_dir =
        Path::new("../../noir-examples/noir-passport/merkle_age_check/benchmark-inputs/tbs_720/test");

    inputs
        .save_all(base_dir)
        .expect("Failed to write TOML files");

    println!("  Written: {}/t_add_dsc_720.toml", base_dir.display());
    println!("  Written: {}/t_add_id_data_720.toml", base_dir.display());
    println!(
        "  Written: {}/t_add_integrity_commit.toml",
        base_dir.display()
    );
    println!("  Written: {}/t_attest.toml", base_dir.display());
    println!();

    // === Summary ===
    println!("================================================================");
    println!("  Generation Complete");
    println!("================================================================");
    println!();
    println!("  TBS certificate len: {}", inputs.add_dsc.tbs_certificate_len);
    println!("  DSC pubkey offset: {}", inputs.add_id_data.dsc_pubkey_offset_in_dsc_cert);
    println!("  DG1 hash offset: {}", inputs.add_integrity.dg1_hash_offset);
    println!(
        "  Country: \"{}\"",
        inputs.add_dsc.country
    );
    println!("  Salt chain: {} -> {}", inputs.add_dsc.salt, inputs.add_id_data.salt_out);
    println!();
    println!("  Computed commitments (Poseidon2):");
    println!("    comm_out_1 (dsc->id_data):     {}", inputs.add_id_data.comm_in);
    println!("    private_nullifier:              {}", inputs.add_integrity.private_nullifier);
    println!("    comm_out_2 (id_data->integrity): {}", inputs.add_integrity.comm_in);
    println!("    sod_hash:                       {}", inputs.attest.sod_hash);
    println!();
    println!("Remaining manual steps:");
    println!("  1. Run circuits 1-3 sequentially to verify commitments");
    println!("  2. Insert Merkle leaf into sequencer tree, get root + path");
    println!("  3. Update t_attest.toml with root/path/index, run -> attestation");
}
