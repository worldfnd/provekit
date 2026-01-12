use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{
        file::{read, read_hash_config, write},
        runtime_hash, Prover,
    },
    provekit_prover::Prove,
    std::path::PathBuf,
    tracing::{info, instrument},
};

/// Prove a prepared Noir program
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prove")]
pub struct Args {
    /// path to the prepared proof scheme
    #[argh(positional)]
    prover_path: PathBuf,

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
        // Read the hash config from the file header
        let hash_config = read_hash_config::<Prover>(&self.prover_path)
            .context("while reading hash config from prover file")?;

        info!(?hash_config, "Using hash configuration");

        // Use dispatch macro to read with correct types and prove
        runtime_hash!(hash_config, |MerkleConfig, PowStrategy| {
            let prover: Prover<MerkleConfig, PowStrategy> =
                read(&self.prover_path).context("while reading Provekit Prover")?;

            let (constraints, witnesses) = prover.size();
            info!(constraints, witnesses, hash = ?hash_config, "Read Noir proof scheme");

            // Generate the proof
            let proof = prover
                .prove(&self.input_path)
                .context("While proving Noir program statement")?;

            // Store the proof to file
            write(&proof, &self.proof_path).context("while writing proof")?;

            Ok(())
        })
    }
}
