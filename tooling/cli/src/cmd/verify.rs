use {
    super::{util::resolve_key_path, Command},
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_backend_bn254::{Bn254Field, ProvekitProof, Verifier, Verify},
    provekit_common::file::read,
    std::path::PathBuf,
    tracing::instrument,
};

/// Verify a Noir proof.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "verify")]
pub struct Args {
    /// path to the ProveKit Verifier (PKV) key (default: `<circuit>.pkv`)
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

        let (verifier, proof) = rayon::join(
            || read::<Verifier>(&verifier_path).context("while reading Provekit Verifier"),
            || read::<ProvekitProof<Bn254Field>>(&self.proof_path).context("while reading proof"),
        );
        let mut verifier = verifier?;
        let proof = proof?;

        verifier
            .verify(&proof)
            .context("While verifying Noir proof")?;

        Ok(())
    }
}
