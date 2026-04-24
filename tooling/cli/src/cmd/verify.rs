use {
    super::{util::resolve_key_path, Command},
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::read, NoirProof, Verifier},
    provekit_verifier::Verify,
    std::path::PathBuf,
    tracing::instrument,
};

/// Verify a Noir proof.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "verify")]
pub struct Args {
    /// path to the verifier key (default: <circuit>.pkv)
    #[argh(option, long = "verifier", short = 'v')]
    verifier_path: Option<PathBuf>,

    /// path to the proof file
    #[argh(option, long = "proof", default = "PathBuf::from(\"./proof.np\")")]
    proof_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let verifier_path = resolve_key_path(self.verifier_path.as_deref(), "pkv")?;

        // Independent I/O + decompression — load both in parallel.
        let (verifier, proof) = rayon::join(
            || read::<Verifier>(&verifier_path).context("while reading Provekit Verifier"),
            || read::<NoirProof>(&self.proof_path).context("while reading proof"),
        );
        let mut verifier = verifier?;
        let proof = proof?;

        verifier
            .verify(&proof)
            .context("While verifying Noir proof")?;

        Ok(())
    }
}
