use {
    super::Command,
    crate::verify,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::{read, read_hash_type},
        hash::{Blake3, HashType, Sha2, Sha3, Skyscraper},
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
            HashType::Skyscraper => verify!(self, Skyscraper),
            HashType::Sha2 => verify!(self, Sha2),
            HashType::Sha3 => verify!(self, Sha3),
            HashType::Blake3 => verify!(self, Blake3)
        }
        Ok(())
    }
}
