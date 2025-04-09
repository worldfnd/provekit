use {
    super::Command,
    crate::file::read_bin,
    anyhow::{Context, Result},
    argh::FromArgs,
    noir_r1cs::{self, NoirProofScheme},
    std::{fs::File, io::Read, path::PathBuf},
    tracing::instrument,
};

/// Prove a prepared Noir program
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "prove")]
pub struct ProveArgs {
    /// path to the compiled Noir program
    #[argh(positional)]
    scheme_path: PathBuf,

    /// path to the input values
    #[argh(positional)]
    input_path: PathBuf,

    /// path to store proof file
    #[argh(option, default = "PathBuf::from(\"./proof.bin\")")]
    proof_path: PathBuf,

    /// path to store Gnark proof file
    #[argh(option, default = "PathBuf::from(\"./gnark_proof.bin\")")]
    gnark_out: PathBuf,
}

impl Command for ProveArgs {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        // Read the scheme
        let scheme: NoirProofScheme =
            read_bin(&self.scheme_path).context("while reading Noir proof scheme")?;

        // Read the input toml
        let mut file = File::open(&self.input_path).context("while opening input file")?;
        let mut input_toml =
            String::with_capacity(file.metadata().map(|m| m.len() as usize).unwrap_or(0));
        file.read_to_string(&mut input_toml)
            .context("while reading input file")?;

        // Generate the proof
        let proof = scheme
            .prove(&input_toml)
            .context("While proving Noir program statement")?;

        // Verify the proof
        scheme
            .verify(&proof)
            .context("While verifying Noir proof")?;

        // TODO: Store the proof to file

        Ok(())
    }
}
