use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    noir_r1cs::{self, read, write, NoirProofScheme},
    noir_tools::execute_program_witness,
    std::path::PathBuf,
    tracing::{info, instrument},
};

/// Prove a prepared Noir program
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prove")]
pub struct Args {
    /// path to the compile Noir program
    #[argh(positional)]
    program_path: PathBuf,

    /// path to the prepared proof scheme
    #[argh(positional)]
    scheme_path: PathBuf,

    /// path to the input values
    #[argh(positional)]
    witness_path: PathBuf,

    /// path to store proof file
    #[argh(
        option,
        long = "out",
        short = 'o',
        default = "PathBuf::from(\"./proof.np\")"
    )]
    proof_path: PathBuf,

    /// path to store Gnark proof file
    #[argh(
        option,
        long = "gnark-out",
        default = "PathBuf::from(\"./gnark_proof.bin\")"
    )]
    gnark_out: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        // Read the scheme
        let scheme: NoirProofScheme =
            read(&self.scheme_path).context("while reading Noir proof scheme")?;
        let (constraints, witnesses) = scheme.size();
        info!(constraints, witnesses, "Read Noir proof scheme");

        let witness_map = execute_program_witness(&self.program_path, &self.witness_path)?;

        // Generate the proof
        let proof = scheme
            .prove(&witness_map)
            .context("While proving Noir program statement")?;

        // Verify the proof (not in release build)
        #[cfg(test)]
        scheme
            .verify(&proof)
            .context("While verifying Noir proof")?;

        // Store the proof to file
        write(&proof, &self.proof_path).context("while writing proof")?;

        Ok(())
    }
}
