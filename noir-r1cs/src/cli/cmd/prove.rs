use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    noir_artifact_cli::fs::inputs::read_inputs_from_file,
    noir_r1cs::{self, read, write, NoirProofScheme},
    std::path::PathBuf,
    tracing::{info, instrument},
};

/// Prove a prepared Noir program
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prove")]
pub struct Args {
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

        // Generate the witness
        let (input_map, _expected_return) =
            read_inputs_from_file(&self.witness_path, &scheme.program.abi)?;
        let witness_map = scheme.generate_witness(&input_map)?;

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
