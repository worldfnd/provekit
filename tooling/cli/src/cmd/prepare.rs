use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::write, runtime_hash, HashConfig, NoirProofScheme, Prover, Verifier},
    provekit_r1cs_compiler::NoirProofSchemeBuilder,
    std::path::PathBuf,
    tracing::instrument,
};

/// Prepare a Noir program for proving
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prepare")]
pub struct Args {
    /// path to the compiled Noir program
    #[argh(positional)]
    program_path: PathBuf,

    /// output path for the prepared proof scheme
    #[argh(
        option,
        long = "pkp",
        short = 'p',
        default = "PathBuf::from(\"noir_proof_scheme.pkp\")"
    )]
    pkp_path: PathBuf,

    /// output path for the verifier
    #[argh(
        option,
        long = "pkv",
        short = 'v',
        default = "PathBuf::from(\"noir_proof_scheme.pkv\")"
    )]
    pkv_path: PathBuf,

    /// hash algorithm for Merkle commitments (skyscraper, sha256, keccak,
    /// blake3)
    #[argh(option, long = "hash", default = "String::from(\"skyscraper\")")]
    hash: String,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        // Parse hash configuration
        let hash_config = HashConfig::from_str(&self.hash)
            .with_context(|| format!("Invalid hash configuration: {}", self.hash))?;

        // Use dispatch macro to build the scheme with correct types
        runtime_hash!(hash_config, |MerkleConfig, PowStrategy| {
            let scheme =
                NoirProofScheme::<MerkleConfig, PowStrategy>::from_file(&self.program_path)
                    .context("while compiling Noir program")?;

            // Convert to prover and verifier
            let prover = Prover::from_noir_proof_scheme(scheme.clone());
            let verifier = Verifier::from_noir_proof_scheme(scheme);

            // Write to files (hash_config is stored in serialized data)
            write(&prover, &self.pkp_path).context("while writing Provekit Prover")?;
            write(&verifier, &self.pkv_path).context("while writing Provekit Verifier")?;

            Ok(())
        })
    }
}
