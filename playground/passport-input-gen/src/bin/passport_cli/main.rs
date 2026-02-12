/// Unified CLI for passport-input-gen.
///
/// Runtime selection of:
///   - TBS variant: 720 or 1300
///   - Mode: Generate TOML files  or  Generate proofs directly (no TOML)
///
/// Prove mode generates proofs for all t_add_* circuits (excluding t_attest)
/// using the JSON -> InputMap -> prover.prove() pipeline.
mod profiling_alloc;
mod span_stats;

use {
    anyhow::{Context, Result},
    noirc_abi::input_parser::Format,
    passport_input_gen::{
        mock_generator::{
            dg1_bytes_with_birthdate_expiry_date, generate_fake_sod,
            generate_fake_sod_with_padded_tbs,
        },
        mock_keys::{MOCK_CSCA_PRIV_KEY_B64, MOCK_DSC_PRIV_KEY_B64},
        Binary, MerkleAge1300Config, MerkleAge1300Inputs, MerkleAge720Config, MerkleAge720Inputs,
        PassportReader,
    },
    profiling_alloc::ProfilingAllocator,
    provekit_prover::Prove,
    span_stats::SpanStats,
    tracing::instrument,
    tracing_subscriber::{layer::SubscriberExt, Registry},
};

#[global_allocator]
static ALLOCATOR: ProfilingAllocator = ProfilingAllocator::new();

use {
    base64::{engine::general_purpose::STANDARD, Engine as _},
    rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey, RsaPublicKey},
    std::{
        io::{self, Write as _},
        path::{Path, PathBuf},
    },
};

// ============================================================================
// Runtime prompts
// ============================================================================

fn prompt(question: &str) -> String {
    print!("{}", question);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

enum TbsChoice {
    Tbs720,
    Tbs1300,
}

enum Mode {
    Toml,
    Prove,
}

fn prompt_tbs_variant() -> TbsChoice {
    println!("Select TBS case:");
    println!("  1) TBS-720  (3 add circuits)");
    println!("  2) TBS-1300 (4 add circuits)");
    loop {
        let answer = prompt("> ");
        match answer.as_str() {
            "1" | "720" => return TbsChoice::Tbs720,
            "2" | "1300" => return TbsChoice::Tbs1300,
            _ => println!("  Invalid choice. Enter 1 or 2."),
        }
    }
}

fn prompt_mode() -> Mode {
    println!("\nSelect mode:");
    println!("  1) Generate TOML files");
    println!("  2) Generate proofs (direct, no TOML)");
    loop {
        let answer = prompt("> ");
        match answer.as_str() {
            "1" | "toml" => return Mode::Toml,
            "2" | "prove" => return Mode::Prove,
            _ => println!("  Invalid choice. Enter 1 or 2."),
        }
    }
}

// ============================================================================
// Mock data helpers (consolidated from old generate_720/1300_inputs binaries)
// ============================================================================

fn load_mock_keys() -> (RsaPrivateKey, RsaPublicKey, RsaPrivateKey, RsaPublicKey) {
    let csca_der = STANDARD
        .decode(MOCK_CSCA_PRIV_KEY_B64)
        .expect("Failed to decode CSCA private key");
    let csca_priv =
        RsaPrivateKey::from_pkcs8_der(&csca_der).expect("Failed to parse CSCA private key");
    let csca_pub = csca_priv.to_public_key();

    let dsc_der = STANDARD
        .decode(MOCK_DSC_PRIV_KEY_B64)
        .expect("Failed to decode DSC private key");
    let dsc_priv =
        RsaPrivateKey::from_pkcs8_der(&dsc_der).expect("Failed to parse DSC private key");
    let dsc_pub = dsc_priv.to_public_key();

    (csca_priv, csca_pub, dsc_priv, dsc_pub)
}

fn generate_720_inputs(
    csca_priv: &RsaPrivateKey,
    csca_pub: &RsaPublicKey,
    dsc_priv: &RsaPrivateKey,
    dsc_pub: &RsaPublicKey,
) -> Result<MerkleAge720Inputs> {
    println!("\n--- Generating TBS-720 inputs ---");

    let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");
    println!("  DG1: {} bytes (DOB: 070101, Expiry: 320101)", dg1.len());

    let sod = generate_fake_sod(&dg1, dsc_priv, dsc_pub, csca_priv, csca_pub);
    println!("  SOD generated (mock)");

    let reader = PassportReader::new(Binary::from_slice(&dg1), sod, true, Some(csca_pub.clone()));
    let csca_idx = reader.validate().context("Passport validation failed")?;
    println!("  Validation passed (CSCA key index: {})", csca_idx);

    let config = MerkleAge720Config {
        current_date: 1735689600, // Jan 1, 2025 00:00:00 UTC
        min_age_required: 18,
        max_age_required: 0,
        ..Default::default()
    };

    let inputs = reader
        .to_merkle_age_720_inputs(csca_idx, config)
        .context("Failed to generate 720 circuit inputs")?;
    println!("  Circuit inputs generated for 4 circuits");

    Ok(inputs)
}

fn generate_1300_inputs(
    csca_priv: &RsaPrivateKey,
    csca_pub: &RsaPublicKey,
    dsc_priv: &RsaPrivateKey,
    dsc_pub: &RsaPublicKey,
) -> Result<MerkleAge1300Inputs> {
    println!("\n--- Generating TBS-1300 inputs ---");

    let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");
    println!("  DG1: {} bytes (DOB: 070101, Expiry: 320101)", dg1.len());

    let sod = generate_fake_sod_with_padded_tbs(&dg1, dsc_priv, dsc_pub, csca_priv, csca_pub, 850);
    println!("  SOD generated (mock, padded TBS = 850 bytes)");

    let reader = PassportReader::new(Binary::from_slice(&dg1), sod, true, Some(csca_pub.clone()));
    let csca_idx = reader.validate().context("Passport validation failed")?;
    println!("  Validation passed (CSCA key index: {})", csca_idx);

    let config = MerkleAge1300Config {
        current_date: 1735689600,
        min_age_required: 17,
        max_age_required: 0,
        ..Default::default()
    };

    let inputs = reader
        .to_merkle_age_1300_inputs(csca_idx, config)
        .context("Failed to generate 1300 circuit inputs")?;
    println!("  Circuit inputs generated for 5 circuits");

    Ok(inputs)
}

// ============================================================================
// Proving helpers
// ============================================================================

/// Load a prover from its .pkp file, convert circuit inputs to InputMap via
/// JSON serialization + ABI parsing, generate the proof, and write it to disk.
#[instrument(skip_all, fields(circuit_name = %circuit_name))]
fn prove_circuit<T: serde::Serialize>(
    circuit_name: &str,
    inputs: &T,
    pkp_path: &Path,
    proof_path: &Path,
) -> Result<()> {
    println!(
        "\n  [{circuit_name}] Loading prover from: {}",
        pkp_path.display()
    );
    let prover: provekit_common::Prover = provekit_common::file::read(pkp_path)
        .with_context(|| format!("Reading prover key for {circuit_name}"))?;

    let (num_constraints, num_witnesses) = prover.size();
    println!(
        "  [{circuit_name}] Scheme size: {num_constraints} constraints, {num_witnesses} witnesses"
    );

    println!("  [{circuit_name}] Converting inputs -> JSON -> InputMap...");
    let json = serde_json::to_string(inputs)
        .with_context(|| format!("Serializing {circuit_name} inputs to JSON"))?;
    let input_map = Format::Json
        .parse(&json, prover.witness_generator.abi())
        .map_err(|e| anyhow::anyhow!("ABI parse error for {circuit_name}: {e}"))?;

    println!("  [{circuit_name}] Generating proof...");
    let proof = prover
        .prove(input_map)
        .with_context(|| format!("Proving {circuit_name}"))?;

    println!(
        "  [{circuit_name}] Writing proof to: {}",
        proof_path.display()
    );
    provekit_common::file::write(&proof, proof_path)
        .with_context(|| format!("Writing proof for {circuit_name}"))?;

    println!("  [{circuit_name}] Done.");

    Ok(())
}

fn prove_720(inputs: &MerkleAge720Inputs, benchmark_dir: &Path) -> Result<()> {
    println!("\n  Proving TBS-720 chain (3 circuits, excluding t_attest)...");

    prove_circuit(
        "t_add_dsc_720",
        &inputs.add_dsc,
        &benchmark_dir.join("t_add_dsc_720-prover.pkp"),
        &benchmark_dir.join("t_add_dsc_720-proof.np"),
    )?;

    prove_circuit(
        "t_add_id_data_720",
        &inputs.add_id_data,
        &benchmark_dir.join("t_add_id_data_720-prover.pkp"),
        &benchmark_dir.join("t_add_id_data_720-proof.np"),
    )?;

    prove_circuit(
        "t_add_integrity_commit",
        &inputs.add_integrity,
        &benchmark_dir.join("t_add_integrity_commit-prover.pkp"),
        &benchmark_dir.join("t_add_integrity_commit-proof.np"),
    )?;

    Ok(())
}

fn prove_1300(inputs: &MerkleAge1300Inputs, benchmark_dir: &Path) -> Result<()> {
    println!("\n  Proving TBS-1300 chain (4 circuits, excluding t_attest)...");

    prove_circuit(
        "t_add_dsc_hash_1300",
        &inputs.add_dsc_hash,
        &benchmark_dir.join("t_add_dsc_hash_1300-prover.pkp"),
        &benchmark_dir.join("t_add_dsc_hash_1300-proof.np"),
    )?;

    prove_circuit(
        "t_add_dsc_verify_1300",
        &inputs.add_dsc_verify,
        &benchmark_dir.join("t_add_dsc_verify_1300-prover.pkp"),
        &benchmark_dir.join("t_add_dsc_verify_1300-proof.np"),
    )?;

    prove_circuit(
        "t_add_id_data_1300",
        &inputs.add_id_data,
        &benchmark_dir.join("t_add_id_data_1300-prover.pkp"),
        &benchmark_dir.join("t_add_id_data_1300-proof.np"),
    )?;

    prove_circuit(
        "t_add_integrity_commit",
        &inputs.add_integrity,
        &benchmark_dir.join("t_add_integrity_commit-prover.pkp"),
        &benchmark_dir.join("t_add_integrity_commit-proof.np"),
    )?;

    Ok(())
}

// ============================================================================
// TOML output helpers
// ============================================================================

fn save_720_toml(inputs: &MerkleAge720Inputs, base_dir: &Path) -> Result<()> {
    inputs
        .save_all(base_dir)
        .context("Failed to write TOML files")?;
    println!("\n  Written:");
    println!("    {}/t_add_dsc_720.toml", base_dir.display());
    println!("    {}/t_add_id_data_720.toml", base_dir.display());
    println!("    {}/t_add_integrity_commit.toml", base_dir.display());
    println!("    {}/t_attest.toml", base_dir.display());
    Ok(())
}

fn save_1300_toml(inputs: &MerkleAge1300Inputs, base_dir: &Path) -> Result<()> {
    inputs
        .save_all(base_dir)
        .context("Failed to write TOML files")?;
    println!("\n  Written:");
    println!("    {}/t_add_dsc_hash_1300.toml", base_dir.display());
    println!("    {}/t_add_dsc_verify_1300.toml", base_dir.display());
    println!("    {}/t_add_id_data_1300.toml", base_dir.display());
    println!("    {}/t_add_integrity_commit.toml", base_dir.display());
    println!("    {}/t_attest.toml", base_dir.display());
    Ok(())
}

// ============================================================================
// Summary printers
// ============================================================================

fn print_720_summary(inputs: &MerkleAge720Inputs) {
    println!("\n  Summary:");
    println!(
        "    TBS certificate len: {}",
        inputs.add_dsc.tbs_certificate_len
    );
    println!(
        "    DSC pubkey offset:   {}",
        inputs.add_id_data.dsc_pubkey_offset_in_dsc_cert
    );
    println!(
        "    DG1 hash offset:     {}",
        inputs.add_integrity.dg1_hash_offset
    );
    println!("    Country:             \"{}\"", inputs.add_dsc.country);
    println!(
        "    Salt chain:          {} -> {}",
        inputs.add_dsc.salt, inputs.add_id_data.salt_out
    );
    println!();
    println!("  Computed commitments (Poseidon2):");
    println!(
        "    comm_out_1 (dsc->id_data):      {}",
        inputs.add_id_data.comm_in
    );
    println!(
        "    private_nullifier:               {}",
        inputs.add_integrity.private_nullifier
    );
    println!(
        "    comm_out_2 (id_data->integrity): {}",
        inputs.add_integrity.comm_in
    );
    println!(
        "    sod_hash:                        {}",
        inputs.attest.sod_hash
    );
}

fn print_1300_summary(inputs: &MerkleAge1300Inputs) {
    println!("\n  Summary:");
    println!(
        "    TBS certificate len: {}",
        inputs.add_dsc_verify.tbs_certificate_len
    );
    println!(
        "    SHA256 state1:       {:?}",
        inputs.add_dsc_verify.state1
    );
    println!(
        "    DSC pubkey offset:   {}",
        inputs.add_id_data.dsc_pubkey_offset_in_dsc_cert
    );
    println!(
        "    DG1 hash offset:     {}",
        inputs.add_integrity.dg1_hash_offset
    );
    println!(
        "    Country:             \"{}\"",
        inputs.add_dsc_verify.country
    );
    println!(
        "    Salt chain:          {} -> {} -> {}",
        inputs.add_dsc_hash.salt, inputs.add_dsc_verify.salt_out, inputs.add_id_data.salt_out,
    );
    println!();
    println!("  Computed commitments (Poseidon2):");
    println!(
        "    comm_out_hash (dsc_hash->dsc_verify):  {}",
        inputs.add_dsc_verify.comm_in
    );
    println!(
        "    comm_out_verify (dsc_verify->id_data): {}",
        inputs.add_id_data.comm_in
    );
    println!(
        "    comm_out_id (id_data->integrity):      {}",
        inputs.add_integrity.comm_in
    );
    println!(
        "    private_nullifier:                      {}",
        inputs.add_integrity.private_nullifier
    );
    println!(
        "    sod_hash:                               {}",
        inputs.attest.sod_hash
    );
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<()> {
    // Initialize logging/tracing with SpanStats for detailed performance metrics
    let subscriber = Registry::default().with(SpanStats);
    let _ = tracing::subscriber::set_global_default(subscriber);

    println!("================================================================");
    println!("  Passport Input Generator & Prover CLI");
    println!("================================================================\n");

    let tbs = prompt_tbs_variant();
    let mode = prompt_mode();

    // Load mock RSA key pairs
    println!("\nStep 1: Loading mock RSA key pairs...");
    let (csca_priv, csca_pub, dsc_priv, dsc_pub) = load_mock_keys();
    println!("  CSCA key loaded (RSA-4096)");
    println!("  DSC key loaded (RSA-2048)");

    let cwd = std::env::current_dir().context("Failed to get current working directory")?;
    let benchmark_dir: PathBuf =
        cwd.join("noir-examples/noir-passport/merkle_age_check/benchmark-inputs");

    match (tbs, mode) {
        (TbsChoice::Tbs720, Mode::Toml) => {
            let inputs = generate_720_inputs(&csca_priv, &csca_pub, &dsc_priv, &dsc_pub)?;
            let toml_dir = benchmark_dir.join("tbs_720/test");
            save_720_toml(&inputs, &toml_dir)?;
            print_720_summary(&inputs);
        }
        (TbsChoice::Tbs720, Mode::Prove) => {
            let inputs = generate_720_inputs(&csca_priv, &csca_pub, &dsc_priv, &dsc_pub)?;
            print_720_summary(&inputs);
            prove_720(&inputs, &benchmark_dir)?;
            println!("\n  All TBS-720 proofs generated successfully.");
        }
        (TbsChoice::Tbs1300, Mode::Toml) => {
            let inputs = generate_1300_inputs(&csca_priv, &csca_pub, &dsc_priv, &dsc_pub)?;
            let toml_dir = benchmark_dir.join("tbs_1300/test");
            save_1300_toml(&inputs, &toml_dir)?;
            print_1300_summary(&inputs);
        }
        (TbsChoice::Tbs1300, Mode::Prove) => {
            let inputs = generate_1300_inputs(&csca_priv, &csca_pub, &dsc_priv, &dsc_pub)?;
            print_1300_summary(&inputs);
            prove_1300(&inputs, &benchmark_dir)?;
            println!("\n  All TBS-1300 proofs generated successfully.");
        }
    }

    println!("\n================================================================");
    println!("  Complete");
    println!("================================================================");
    Ok(())
}
