use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::{read, read_hash_config},
        runtime_hash, Verifier,
    },
    provekit_verifier::Verify,
    std::path::PathBuf,
    tracing::instrument,
};

/// Verify a Noir proof
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "verify")]
pub struct Args {
    /// path to the verifier
    #[argh(positional)]
    verifier_path: PathBuf,

    /// path to the proof file
    #[argh(positional)]
    proof_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        // Read the hash config from the file header
        let hash_config = read_hash_config::<Verifier>(&self.verifier_path)
            .context("while reading hash config from verifier file")?;

        // Use dispatch macro to read with correct types and verify
        runtime_hash!(hash_config, |MerkleConfig, PowStrategy| {
            let mut verifier: Verifier<MerkleConfig, PowStrategy> =
                read(&self.verifier_path).context("while reading Provekit Verifier")?;

            // Read the proof
            let proof = read(&self.proof_path).context("while reading proof")?;

            // Verify the proof
            verifier
                .verify(&proof)
                .context("While verifying Noir proof")?;

            Ok(())
        })
    }
}
