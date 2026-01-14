use {
    super::Command,
    crate::prove,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::{read, read_hash_type, write},
        hash::{Blake3, HashType, Sha2, Sha3, Skyscraper},
        Prover,
    },
    provekit_prover::Prove,
    std::path::PathBuf,
    tracing::{info, instrument},
};
#[cfg(test)]
use {provekit_common::Verifier, provekit_verifier::Verify};

/// Prove a prepared Noir program
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prove")]
pub struct Args {
    /// path to the prepared proof scheme
    #[argh(positional)]
    prover_path: PathBuf,

    #[cfg(test)]
    /// path to the verifier
    #[argh(positional)]
    verifier_path: PathBuf,

    /// path to the input values
    #[argh(positional)]
    input_path: PathBuf,

    /// path to store proof file
    #[argh(
        option,
        long = "out",
        short = 'o',
        default = "PathBuf::from(\"./proof.np\")"
    )]
    proof_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let hash_type = read_hash_type(&self.prover_path)?;
        info!(hash_type = ?hash_type, "Hash Type");

        match hash_type {
            HashType::Skyscraper => prove!(self, hash_type, Skyscraper),
            HashType::Sha2 => prove!(self, hash_type, Sha2),
            HashType::Sha3 => prove!(self, hash_type, Sha3),
            HashType::Blake3 => prove!(self, hash_type, Blake3),
        }
        Ok(())
    }
}
