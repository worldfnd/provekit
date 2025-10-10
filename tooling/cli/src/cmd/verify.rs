use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::read, Verifier},
    provekit_verifier::Verify,
    std::path::PathBuf,
    tracing::instrument,
};

/// Prove a prepared Noir program
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "verify")]
pub struct Args {
    /// path to the compiled Noir program
    #[argh(positional)]
    verifier_path: PathBuf,

    /// path to the proof file
    #[argh(positional)]
    proof_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        // Read the scheme
        let mut verifier: Verifier =
            read(&self.verifier_path).context("while reading Provekit Verifier")?;

        // Read the proof
        let proof = read(&self.proof_path).context("while reading proof")?;

        // Verify the proof
        verifier
            .verify(&proof)
            .context("While verifying Noir proof")?;

        Ok(())
    }
}
