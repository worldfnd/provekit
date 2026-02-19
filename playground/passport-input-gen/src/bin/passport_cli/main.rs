/// Unified CLI for passport-input-gen.
///
/// Runtime selection of:
///   - Circuit variant: TBS size, key sizes, padding, hash algorithms
///   - Mode: Generate TOML files  or  Generate proofs directly (no TOML)
///
/// Prove mode generates proofs for all 4 circuits using the
/// JSON -> InputMap -> prover.prove() pipeline.
mod profiling_alloc;
mod span_stats;

use {
    anyhow::{Context, Result},
    argh::FromArgs,
    noirc_abi::input_parser::Format,
    passport_input_gen::{
        mock_generator::{
            dg1_bytes_with_birthdate_expiry_date, generate_sod_with_padded_tbs_and_config,
            MockConfig,
        },
        mock_keys::{MOCK_CSCA_PRIV_KEY_B64, MOCK_DSC_PRIV_KEY_B64},
        parser::types::{DigestAlgorithm, RsaKeyBits, RsaPadding},
        AttestConfig, Binary, CircuitInputSet, CircuitVariant, PassportCircuitInputs,
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
        fs::File,
        io::{BufWriter, Write as _},
        path::Path,
        sync::Mutex,
    },
};

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
    /// TBS size: 700, 1000, 1200, or 1600 (default: 700)
    #[argh(option, default = "700")]
    tbs_size: usize,

    /// CSCA key size in bits: 1024, 2048, 3072, 4096, 6144 (default: 4096)
    #[argh(option, default = "String::from(\"4096\")")]
    csca_key_bits: String,

    /// DSC key size in bits: 1024, 2048, 3072, 4096 (default: 2048)
    #[argh(option, default = "String::from(\"2048\")")]
    dsc_key_bits: String,

    /// CSCA padding: pkcs or pss (default: pkcs)
    #[argh(option, default = "String::from(\"pkcs\")")]
    csca_padding: String,

    /// DSC padding: pkcs or pss (default: pkcs)
    #[argh(option, default = "String::from(\"pkcs\")")]
    dsc_padding: String,

    /// signed-attributes hash: sha1, sha224, sha256, sha384, sha512 (default:
    /// sha256)
    #[argh(option, default = "String::from(\"sha256\")")]
    sa_hash: String,

    /// DG hash: sha1, sha224, sha256, sha384, sha512 (default: sha256)
    #[argh(option, default = "String::from(\"sha256\")")]
    dg_hash: String,

    /// mode: "toml" or "prove"
    #[argh(option)]
    mode: String,

    /// output directory for TOML files (default: auto-derived from variant)
    #[argh(option)]
    output_dir: Option<String>,

    /// save per-circuit log files during prove mode
    #[argh(switch)]
    save_logs: bool,

    /// directory for log files (default: output_dir/logs)
    #[argh(option)]
    log_dir: Option<String>,
}

impl Args {
    /// Build a `CircuitVariant` from CLI arguments.
    fn to_circuit_variant(&self) -> Result<CircuitVariant> {
        let csca_key_bits = RsaKeyBits::from_str(&self.csca_key_bits)
            .ok_or_else(|| anyhow::anyhow!("Invalid --csca-key-bits: {}", self.csca_key_bits))?;
        let dsc_key_bits = RsaKeyBits::from_str(&self.dsc_key_bits)
            .ok_or_else(|| anyhow::anyhow!("Invalid --dsc-key-bits: {}", self.dsc_key_bits))?;
        let csca_padding = RsaPadding::from_str(&self.csca_padding)
            .ok_or_else(|| anyhow::anyhow!("Invalid --csca-padding: {}", self.csca_padding))?;
        let dsc_padding = RsaPadding::from_str(&self.dsc_padding)
            .ok_or_else(|| anyhow::anyhow!("Invalid --dsc-padding: {}", self.dsc_padding))?;
        let sa_hash = DigestAlgorithm::from_name(&self.sa_hash)
            .ok_or_else(|| anyhow::anyhow!("Invalid --sa-hash: {}", self.sa_hash))?;
        let dg_hash = DigestAlgorithm::from_name(&self.dg_hash)
            .ok_or_else(|| anyhow::anyhow!("Invalid --dg-hash: {}", self.dg_hash))?;

        let variant = CircuitVariant {
            tbs_size: self.tbs_size,
            csca_key_bits,
            dsc_key_bits,
            csca_padding,
            dsc_padding,
            sa_hash,
            dg_hash,
        };
        variant
            .validate()
            .map_err(|e| anyhow::anyhow!("Invalid circuit variant: {e}"))?;
        Ok(variant)
    }

    /// Build a `MockConfig` from CLI arguments.
    fn to_mock_config(&self) -> Result<MockConfig> {
        let dg_hash = DigestAlgorithm::from_name(&self.dg_hash)
            .ok_or_else(|| anyhow::anyhow!("Invalid --dg-hash: {}", self.dg_hash))?;
        let sa_hash = DigestAlgorithm::from_name(&self.sa_hash)
            .ok_or_else(|| anyhow::anyhow!("Invalid --sa-hash: {}", self.sa_hash))?;
        let dsc_padding = RsaPadding::from_str(&self.dsc_padding)
            .ok_or_else(|| anyhow::anyhow!("Invalid --dsc-padding: {}", self.dsc_padding))?;
        let csc_padding = RsaPadding::from_str(&self.csca_padding)
            .ok_or_else(|| anyhow::anyhow!("Invalid --csca-padding: {}", self.csca_padding))?;
        Ok(MockConfig {
            dg_hash,
            sa_hash,
            dsc_padding,
            csc_padding,
        })
    }
}

// ============================================================================
// Mock data helpers
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

fn generate_inputs(
    csca_priv: &RsaPrivateKey,
    csca_pub: &RsaPublicKey,
    dsc_priv: &RsaPrivateKey,
    dsc_pub: &RsaPublicKey,
    variant: &CircuitVariant,
    mock_config: &MockConfig,
) -> Result<PassportCircuitInputs> {
    println!("\n--- Generating inputs for variant ---");
    println!("  TBS size: {}", variant.tbs_size);
    println!(
        "  CSCA: RSA-{} {}",
        variant.csca_key_bits, variant.csca_padding
    );
    println!(
        "  DSC:  RSA-{} {}",
        variant.dsc_key_bits, variant.dsc_padding
    );
    println!(
        "  Hash: SA={} DG={}",
        variant.sa_hash.circuit_path(),
        variant.dg_hash.circuit_path()
    );

    let dg1 = dg1_bytes_with_birthdate_expiry_date(b"070101", b"320101");
    println!("  DG1: {} bytes (DOB: 070101, Expiry: 320101)", dg1.len());

    // Generate SOD with TBS padded to a realistic size for the target TBS
    // circuit. Use ~80% of tbs_size as actual TBS length.
    let tbs_actual_len = (variant.tbs_size * 4) / 5;
    let sod = generate_sod_with_padded_tbs_and_config(
        &dg1,
        dsc_priv,
        dsc_pub,
        csca_priv,
        tbs_actual_len,
        mock_config,
    );
    println!(
        "  SOD generated (mock, padded TBS = {} bytes)",
        sod.certificate.tbs.bytes.len()
    );

    let reader = PassportReader::new(Binary::from_slice(&dg1), sod, true, Some(csca_pub.clone()));
    let csca_idx = reader.validate().context("Passport validation failed")?;
    println!("  Validation passed (CSCA key index: {})", csca_idx);

    let config = AttestConfig {
        current_date: 1735689600, // Jan 1, 2025 00:00:00 UTC
        min_age_required: 18,
        max_age_required: 0,
        ..Default::default()
    };

    let inputs = reader
        .to_passport_inputs(csca_idx, variant, config)
        .context("Failed to generate circuit inputs")?;
    println!("  Circuit inputs generated for 4 circuits");

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

fn prove_all(
    inputs: &PassportCircuitInputs,
    pkp_dir: &Path,
    output_dir: &Path,
    log_dir: Option<&Path>,
) -> Result<()> {
    let names = inputs.variant.circuit_names();
    println!("\n  Proving 4-stage pipeline...");
    prove_circuits!(
        pkp_dir,
        output_dir,
        log_dir,
        (&names[0], &inputs.dsc_sig_check),
        (&names[1], &inputs.id_data_sig_check),
        (&names[2], &inputs.integrity),
        (&names[3], &inputs.attest),
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
// Summary printer
// ============================================================================

fn print_summary(inputs: &PassportCircuitInputs) {
    let names = inputs.variant.circuit_names();
    println!("\n  Summary:");
    println!(
        "    TBS certificate len: {}",
        inputs.dsc_sig_check.tbs_certificate.len()
    );
    println!(
        "    Country:             \"{}\"",
        inputs.dsc_sig_check.country
    );
    println!(
        "    CSCA key:            RSA-{} {}",
        inputs.variant.csca_key_bits, inputs.variant.csca_padding
    );
    println!(
        "    DSC key:             RSA-{} {}",
        inputs.variant.dsc_key_bits, inputs.variant.dsc_padding
    );
    println!(
        "    Salt chain:          {} -> {}",
        inputs.dsc_sig_check.salt, inputs.id_data_sig_check.salt_out
    );
    println!();
    println!("  Circuits:");
    for name in &names {
        println!("    {}", name);
    }
    println!();
    println!("  Computed commitments (Poseidon2):");
    println!(
        "    comm_out_1 (dsc->id_data):      {}",
        inputs.id_data_sig_check.comm_in
    );
    println!(
        "    comm_out_2 (id_data->integrity): {}",
        inputs.integrity.comm_in
    );
    println!(
        "    private_nullifier:               {}",
        inputs.integrity.salted_private_nullifier.value
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

    let variant = args.to_circuit_variant()?;
    let mock_config = args.to_mock_config()?;

    let is_toml = match args.mode.as_str() {
        "toml" => true,
        "prove" => false,
        other => {
            anyhow::bail!("Invalid --mode value: \"{other}\". Must be \"toml\" or \"prove\".")
        }
    };

    // Load mock RSA key pairs
    println!("\nStep 1: Loading mock RSA key pairs...");
    let (csca_priv, csca_pub, dsc_priv, dsc_pub) = load_mock_keys();
    println!("  CSCA key loaded (RSA-4096)");
    println!("  DSC key loaded (RSA-2048)");

    let cwd = std::env::current_dir().context("Failed to get current working directory")?;

    // Resolve log directory for prove mode
    let log_dir = if args.save_logs {
        let dir = match args.log_dir {
            Some(d) => cwd.join(d),
            None => cwd.join("benchmark-inputs/logs"),
        };
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Creating log directory: {}", dir.display()))?;
        println!("  Logs will be saved to: {}", dir.display());
        Some(dir)
    } else {
        None
    };

    // Resolve output directory
    let output_dir = match args.output_dir {
        Some(d) => cwd.join(d),
        None => cwd.join(format!(
            "noir-examples/passport/bin/generated-inputs/tbs_{}/rsa/{}/{}/sa_{}/dg_{}",
            variant.tbs_size,
            variant.csca_padding.circuit_path(),
            variant.csca_key_bits,
            variant.sa_hash.circuit_path(),
            variant.dg_hash.circuit_path(),
        )),
    };
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("Creating output directory: {}", output_dir.display()))?;
    println!("  Output directory: {}", output_dir.display());

    // Generate inputs
    let inputs = generate_inputs(
        &csca_priv,
        &csca_pub,
        &dsc_priv,
        &dsc_pub,
        &variant,
        &mock_config,
    )?;
    print_summary(&inputs);

    if is_toml {
        save_toml(&inputs, &output_dir)?;
    } else {
        let pkp_dir = cwd.join("noir-examples/passport/benchmark-inputs/prepare");
        prove_all(&inputs, &pkp_dir, &output_dir, log_dir.as_deref())?;
        println!("\n  All proofs generated successfully.");
    }

    println!("\n================================================================");
    println!("  Complete");
    println!("================================================================");
    Ok(())
}
