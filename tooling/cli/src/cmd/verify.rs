use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::read, NoirProof, Verifier},
    provekit_verifier::Verify,
    std::path::PathBuf,
    tracing::instrument,
};

/// Verify a Noir proof
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
        // Load verifier and proof in parallel (independent I/O + decompression)
        let (verifier, proof) = rayon::join(
            || read::<Verifier>(&self.verifier_path).context("while reading Provekit Verifier"),
            || read::<NoirProof>(&self.proof_path).context("while reading proof"),
        );
        let mut verifier = verifier?;
        let proof = proof?;

        // Verify the proof
        verifier
            .verify(proof)
            .context("While verifying Noir proof")?;

        Ok(())
    }
}
