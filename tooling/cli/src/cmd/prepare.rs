use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    core::hash,
    provekit_common::{file::write, hash::HashType, NoirProofScheme, Prover, Verifier},
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

    /// select hash function
    #[argh(
        option,
        long = "hash",
        short = 'h',
        default = "String::from(\"Skyscraper\")"
    )]
    hash: String,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
    
        let mut scheme = NoirProofScheme::from_file(&self.program_path)
        .context("while compiling Noir program")?;

        let hash_type = HashType::from_str(&self.hash);
        scheme.set_hash_type(hash_type);

        write(
            &Prover::from_noir_proof_scheme(scheme.clone()),
            &self.pkp_path,
        )
        .context("while writing Noir proof scheme")?;

        write(
            &Verifier::from_noir_proof_scheme(scheme), 
            &self.pkv_path
        )
        .context("while writing Noir proof scheme")?;

        Ok(())
    }
}
