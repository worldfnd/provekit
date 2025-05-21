use {
    super::Command,
    acir::{native_types::WitnessMap, FieldElement as NoirFieldElement},
    anyhow::{Context, Result},
    argh::FromArgs,
    noir_r1cs::{self, read, utils::file_io::deserialize_witness_stack, write, NoirProofScheme},
    std::path::PathBuf,
    tracing::{info, instrument},
};

/// Prove a prepared Noir program
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "prove")]
pub struct Args {
    /// path to the compiled Noir program
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
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        // Read the scheme
        let scheme: NoirProofScheme =
            read(&self.scheme_path).context("while reading Noir proof scheme")?;
        let (constraints, witnesses) = scheme.size();
        info!(constraints, witnesses, "Read Noir proof scheme");

        // Read the input toml
        let witness_file_path =
            &PathBuf::from("../noir-examples/noir-r1cs-test-programs/acir_assert_zero/basic.gz");
        let mut witness_stack = deserialize_witness_stack(witness_file_path).unwrap();
        let witness_map: WitnessMap<NoirFieldElement> = witness_stack.pop().unwrap().witness;

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
