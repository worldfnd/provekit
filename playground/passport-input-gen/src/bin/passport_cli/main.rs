/// Unified CLI for passport-input-gen.
///
/// Runtime selection of:
///   - TBS variant: 720 or 1300
///   - Mode: Generate TOML files  or  Generate proofs directly (no TOML)
///
/// Prove mode generates proofs for all circuits (including t_attest)
/// using the JSON -> InputMap -> prover.prove() pipeline.
mod profiling_alloc;
mod span_stats;

use {
    anyhow::{Context, Result},
    argh::FromArgs,
    base64::{engine::general_purpose::STANDARD, Engine as _},
    noirc_abi::input_parser::Format,
    passport_input_gen::{
        mock_generator::{
            dg1_bytes_with_birthdate_expiry_date, generate_sod, generate_sod_with_padded_tbs,
        },
        mock_keys::{MOCK_CSCA_PRIV_KEY_B64, MOCK_DSC_PRIV_KEY_B64},
        Binary, CircuitInputSet, MerkleAge1300Config, MerkleAge1300Inputs, MerkleAge720Config,
        MerkleAge720Inputs, MerkleAgeBaseConfig, PassportReader,
    },
    profiling_alloc::ProfilingAllocator,
    provekit_prover::Prove,
    rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey, RsaPublicKey},
    span_stats::SpanStats,
    std::{
        fs::File,
        io::{BufWriter, Write as _},
        path::{Path, PathBuf},
        sync::Mutex,
    },
    tracing::instrument,
    tracing_subscriber::{layer::SubscriberExt, Registry},
};

#[global_allocator]
static ALLOCATOR: ProfilingAllocator = ProfilingAllocator::new();

// ============================================================================
// Global log sink for tee-ing output to per-circuit log files
// ============================================================================

lazy_static::lazy_static! {
    pub(crate) static ref LOG_SINK: Mutex<Option<BufWriter<File>>> = Mutex::new(None);
}

/// Strip ANSI escape sequences (e.g. `\x1b[0m`, `\x1b[1;32m`) from a string.
pub(crate) fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                              // skip until we hit an ASCII letter (the final byte of the sequence)
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
                continue;
            }
        }
        result.push(c);
    }
    result
}

/// Write a message to the global LOG_SINK (if active), stripping ANSI codes.
pub(crate) fn tee_write_log(msg: &str) {
    if let Ok(mut guard) = LOG_SINK.lock() {
        if let Some(ref mut writer) = *guard {
            let stripped = strip_ansi(msg);
            let _ = writeln!(writer, "{}", stripped);
        }
    }
}

/// Open a log file and set it as the active LOG_SINK.
fn set_log_file(path: &Path) -> Result<()> {
    let file =
        File::create(path).with_context(|| format!("Creating log file: {}", path.display()))?;
    let mut guard = LOG_SINK
        .lock()
        .map_err(|e| anyhow::anyhow!("LOG_SINK lock: {e}"))?;
    *guard = Some(BufWriter::new(file));
    Ok(())
}

/// Flush and close the current LOG_SINK.
fn close_log_file() {
    if let Ok(mut guard) = LOG_SINK.lock() {
        if let Some(ref mut writer) = *guard {
            let _ = writer.flush();
        }
        *guard = None;
    }
}

/// Like `println!` but also writes ANSI-stripped output to LOG_SINK if active.
macro_rules! tee_println {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        println!("{}", msg);
        $crate::tee_write_log(&msg);
    }};
}

// ============================================================================
// CLI arguments
// ============================================================================

/// Passport Input Generator & Prover CLI
#[derive(FromArgs)]
struct Args {
    /// tbs variant: 720 or 1300
    #[argh(option)]
    tbs: u16,

    /// mode: "toml" or "prove"
    #[argh(option)]
    mode: String,

    /// output directory for TOML files (default: benchmark-inputs/tbs_{N}/test)
    #[argh(option)]
    output_dir: Option<String>,

    /// save per-circuit log files during prove mode
    #[argh(switch)]
    save_logs: bool,

    /// directory for log files (default: .../benchmark-inputs/logs/test)
    #[argh(option)]
    log_dir: Option<String>,
}

// ============================================================================
// Mock data helpers (consolidated from old generate_720/1300_inputs binaries)
// ============================================================================

fn load_mock_keys() -> Result<(RsaPrivateKey, RsaPublicKey, RsaPrivateKey, RsaPublicKey)> {
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

    Ok((csca_priv, csca_pub, dsc_priv, dsc_pub))
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

    let sod = generate_sod(&dg1, dsc_priv, dsc_pub, csca_priv, csca_pub);
    println!("  SOD generated (mock)");

    let reader = PassportReader::new(Binary::from_slice(&dg1), sod, true, Some(csca_pub.clone()));
    let csca_idx = reader.validate().context("Passport validation failed")?;
    println!("  Validation passed (CSCA key index: {})", csca_idx);

    let config = MerkleAge720Config {
        base: MerkleAgeBaseConfig {
            current_date: 1735689600, // Jan 1, 2025 00:00:00 UTC
            min_age_required: 18,
            max_age_required: 0,
            ..Default::default()
        },
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

    let sod = generate_sod_with_padded_tbs(&dg1, dsc_priv, dsc_pub, csca_priv, csca_pub, 850);
    println!("  SOD generated (mock, padded TBS = 850 bytes)");

    let reader = PassportReader::new(Binary::from_slice(&dg1), sod, true, Some(csca_pub.clone()));
    let csca_idx = reader.validate().context("Passport validation failed")?;
    println!("  Validation passed (CSCA key index: {})", csca_idx);

    let config = MerkleAge1300Config {
        base: MerkleAgeBaseConfig {
            current_date: 1735689600,
            min_age_required: 18,
            max_age_required: 0,
            ..Default::default()
        },
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
    tee_println!(
        "\n  [{circuit_name}] Loading prover from: {}",
        pkp_path.display()
    );
    let prover: provekit_common::Prover = provekit_common::file::read(pkp_path)
        .with_context(|| format!("Reading prover key for {circuit_name}"))?;

    let (num_constraints, num_witnesses) = prover.size();
    tee_println!(
        "  [{circuit_name}] Scheme size: {num_constraints} constraints, {num_witnesses} witnesses"
    );

    tee_println!("  [{circuit_name}] Converting inputs -> JSON -> InputMap...");
    let json = serde_json::to_string(inputs)
        .with_context(|| format!("Serializing {circuit_name} inputs to JSON"))?;
    let input_map = Format::Json
        .parse(&json, prover.witness_generator.abi())
        .map_err(|e| anyhow::anyhow!("ABI parse error for {circuit_name}: {e}"))?;

    tee_println!("  [{circuit_name}] Generating proof...");
    let proof = prover
        .prove(input_map)
        .with_context(|| format!("Proving {circuit_name}"))?;

    tee_println!(
        "  [{circuit_name}] Writing proof to: {}",
        proof_path.display()
    );
    provekit_common::file::write(&proof, proof_path)
        .with_context(|| format!("Writing proof for {circuit_name}"))?;

    tee_println!("  [{circuit_name}] Done.");

    Ok(())
}

macro_rules! prove_circuits {
    ($pkp_dir:expr, $output_dir:expr, $log_dir:expr, $( ($name:expr, $input:expr) ),+ $(,)?) => {
        $(
            if let Some(dir) = $log_dir {
                set_log_file(&dir.join(format!("{}.log", $name)))?;
            }
            let result = prove_circuit(
                $name,
                $input,
                &$pkp_dir.join(format!("{}-prover.pkp", $name)),
                &$output_dir.join(format!("{}-proof.np", $name)),
            );
            if $log_dir.is_some() {
                close_log_file();
            }
            result?;
        )+
    };
}

fn prove_720(
    inputs: &MerkleAge720Inputs,
    pkp_dir: &Path,
    output_dir: &Path,
    log_dir: Option<&Path>,
) -> Result<()> {
    println!("\n  Proving TBS-720 chain (4 circuits)...");
    prove_circuits!(
        pkp_dir,
        output_dir,
        log_dir,
        ("t_add_dsc_720", &inputs.add_dsc),
        ("t_add_id_data_720", &inputs.add_id_data),
        ("t_add_integrity_commit", &inputs.add_integrity),
        ("t_attest", &inputs.attest),
    );
    Ok(())
}

fn prove_1300(
    inputs: &MerkleAge1300Inputs,
    pkp_dir: &Path,
    output_dir: &Path,
    log_dir: Option<&Path>,
) -> Result<()> {
    println!("\n  Proving TBS-1300 chain (5 circuits)...");
    prove_circuits!(
        pkp_dir,
        output_dir,
        log_dir,
        ("t_add_dsc_hash_1300", &inputs.add_dsc_hash),
        ("t_add_dsc_verify_1300", &inputs.add_dsc_verify),
        ("t_add_id_data_1300", &inputs.add_id_data),
        ("t_add_integrity_commit", &inputs.add_integrity),
        ("t_attest", &inputs.attest),
    );
    Ok(())
}

// ============================================================================
// TOML output helpers
// ============================================================================

fn save_toml(inputs: &dyn CircuitInputSet, base_dir: &Path) -> Result<()> {
    inputs
        .save_all(base_dir)
        .context("Failed to write TOML files")?;
    println!("\n  Written:");
    for name in inputs.circuit_names() {
        println!("    {}/{name}.toml", base_dir.display());
    }
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
    let args: Args = argh::from_env();

    // Initialize logging/tracing with SpanStats for detailed performance metrics
    let subscriber = Registry::default().with(SpanStats);
    let _ = tracing::subscriber::set_global_default(subscriber);

    println!("================================================================");
    println!("  Passport Input Generator & Prover CLI");
    println!("================================================================\n");

    let is_720 = match args.tbs {
        720 => true,
        1300 => false,
        other => anyhow::bail!("Invalid --tbs value: {other}. Must be 720 or 1300."),
    };

    let is_toml = match args.mode.as_str() {
        "toml" => true,
        "prove" => false,
        other => {
            anyhow::bail!("Invalid --mode value: \"{other}\". Must be \"toml\" or \"prove\".")
        }
    };

    // Load mock RSA key pairs
    println!("\nStep 1: Loading mock RSA key pairs...");
    let (csca_priv, csca_pub, dsc_priv, dsc_pub) = load_mock_keys().unwrap();
    println!("  CSCA key loaded (RSA-4096)");
    println!("  DSC key loaded (RSA-2048)");

    let cwd = std::env::current_dir().context("Failed to get current working directory")?;
    let benchmark_dir: PathBuf =
        cwd.join("noir-examples/noir-passport/merkle_age_check/benchmark-inputs");

    // Resolve log directory for prove mode
    let log_dir = if args.save_logs {
        let dir = match args.log_dir {
            Some(d) => cwd.join(d),
            None => {
                cwd.join("noir-examples/noir-passport/merkle_age_check/benchmark-inputs/logs/test")
            }
        };
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Creating log directory: {}", dir.display()))?;
        println!("  Logs will be saved to: {}", dir.display());
        Some(dir)
    } else {
        None
    };

    // Resolve output directory: --output-dir overrides, else default per TBS
    // variant
    let tbs_subdir = if is_720 { "tbs_720" } else { "tbs_1300" };
    let output_dir = match args.output_dir {
        Some(d) => cwd.join(d),
        None => benchmark_dir.join(format!("{tbs_subdir}/test")),
    };
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("Creating output directory: {}", output_dir.display()))?;
    println!("  Output directory: {}", output_dir.display());

    match (is_720, is_toml) {
        (true, true) => {
            let inputs = generate_720_inputs(&csca_priv, &csca_pub, &dsc_priv, &dsc_pub)?;
            save_toml(&inputs, &output_dir)?;
            print_720_summary(&inputs);
        }
        (true, false) => {
            let inputs = generate_720_inputs(&csca_priv, &csca_pub, &dsc_priv, &dsc_pub)?;
            print_720_summary(&inputs);
            prove_720(&inputs, &benchmark_dir, &output_dir, log_dir.as_deref())?;
            println!("\n  All TBS-720 proofs generated successfully.");
        }
        (false, true) => {
            let inputs = generate_1300_inputs(&csca_priv, &csca_pub, &dsc_priv, &dsc_pub)?;
            save_toml(&inputs, &output_dir)?;
            print_1300_summary(&inputs);
        }
        (false, false) => {
            let inputs = generate_1300_inputs(&csca_priv, &csca_pub, &dsc_priv, &dsc_pub)?;
            print_1300_summary(&inputs);
            prove_1300(&inputs, &benchmark_dir, &output_dir, log_dir.as_deref())?;
            println!("\n  All TBS-1300 proofs generated successfully.");
        }
    }

    println!("\n================================================================");
    println!("  Complete");
    println!("================================================================");
    Ok(())
}
