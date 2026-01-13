use {
    super::Command,
    anyhow::{bail, Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::{read, read_hash_type, write},
        hash::{HashType, Sha2, Skyscraper},
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
            HashType::Skyscraper => {
                let prover: Prover<Skyscraper> =
                    read(&self.prover_path).context("while reading Provekit Prover")?;
                let (constraints, witnesses) = prover.size();
                info!(constraints, witnesses, "Read Noir proof scheme");

                // // Read the input toml
                // let input_map = scheme.read_witness(&self.input_path)?;

                // Generate the proof
                let proof = prover
                    .prove(&self.input_path)
                    .context("While proving Noir program statement")?;

                // Verify the proof (not in release build)
                #[cfg(test)]
                {
                    let mut verifier: Verifier<Skyscraper> =
                        read(&self.verifier_path).context("while reading Provekit Verifier")?;
                    verifier
                        .verify(&proof)
                        .context("While verifying Noir proof")?;
                }

                // Store the proof to file
                write(&proof, &self.proof_path, hash_type).context("while writing proof")?;
            }
            HashType::Sha2 => {
                let prover: Prover<Sha2> =
                    read(&self.prover_path).context("while reading Provekit Prover")?;
                let (constraints, witnesses) = prover.size();
                info!(constraints, witnesses, "Read Noir proof scheme");

                // // Read the input toml
                // let input_map = scheme.read_witness(&self.input_path)?;

                // Generate the proof
                let proof = prover
                    .prove(&self.input_path)
                    .context("While proving Noir program statement")?;

                // Verify the proof (not in release build)
                #[cfg(test)]
                {
                    let mut verifier: Verifier<Skyscraper> =
                        read(&self.verifier_path).context("while reading Provekit Verifier")?;
                    verifier
                        .verify(&proof)
                        .context("While verifying Noir proof")?;
                }

                // Store the proof to file
                write(&proof, &self.proof_path, hash_type).context("while writing proof")?;
            }
            _ => panic!("Unsupported hash type for verifier"),
        }
        Ok(())
    }
}
