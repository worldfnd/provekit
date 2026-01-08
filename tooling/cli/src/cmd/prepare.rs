use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::write, hash::HashFunction, NoirProofScheme, Prover, Verifier},
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

    /// hash function to use (skyscraper, sha2, sha3, blake3)
    #[argh(option, long = "hash", default = "String::from(\"skyscraper\")")]
    hash: String,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let hash_function = HashFunction::from_str(&self.hash);
        let scheme = NoirProofScheme::from_file(&self.program_path, hash_function)
            .context("while compiling Noir program")?;
        write(
            &Prover::from_noir_proof_scheme(scheme.clone()),
            &self.pkp_path,
        )
        .context("while writing Noir proof scheme")?;
        write(&Verifier::from_noir_proof_scheme(scheme), &self.pkv_path)
            .context("while writing Noir proof scheme")?;
        Ok(())
    }
}
