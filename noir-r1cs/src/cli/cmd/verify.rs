use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    noir_r1cs::{self, read, NoirProofScheme},
    std::path::PathBuf,
    tracing::{info, instrument},
};

/// Prove a prepared Noir program
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "verify")]
pub struct Args {
    /// path to the compiled Noir program
    #[argh(positional)]
    scheme_path: PathBuf,

    /// path to the proof file
    #[argh(positional)]
    proof_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        // Read the scheme
        let scheme: NoirProofScheme =
            read(&self.scheme_path).context("while reading Noir proof scheme")?;
        let (constraints, witnesses) = scheme.size();
        info!(constraints, witnesses, "Read Noir proof scheme");

        // Read the proof
        let proof = read(&self.proof_path).context("while reading proof")?;

        // Verify the proof
        scheme
            .verify(&proof)
            .context("While verifying Noir proof")?;

        Ok(())
    }
}
