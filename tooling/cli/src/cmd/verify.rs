use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::{read, read_hash_type},
        hash::{HashType, Sha2, Skyscraper},
        Verifier,
    },
    provekit_verifier::Verify,
    std::path::PathBuf,
    tracing::{info, instrument},
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
        let hash_type = read_hash_type(&self.verifier_path)?;
        info!(hash_type = ?hash_type, "Hash Type");

        match hash_type {
            HashType::Skyscraper => {
                let mut verifier: Verifier<Skyscraper> =
                    read(&self.verifier_path).context("while reading Provekit Verifier")?;
                let proof = read(&self.proof_path).context("while reading proof")?;
                verifier
                    .verify(&proof)
                    .context("While verifying Noir proof")?;
            }
            HashType::Sha2 => {
                let mut verifier: Verifier<Sha2> =
                    read(&self.verifier_path).context("while reading Provekit Verifier")?;
                let proof = read(&self.proof_path).context("while reading proof")?;
                verifier
                    .verify(&proof)
                    .context("While verifying Noir proof")?;
            }
            _ => panic!("Unsupported hash type for verifier"),
        }
        Ok(())
    }
}
