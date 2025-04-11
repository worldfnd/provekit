use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    noir_r1cs::{self, read, write, NoirProofScheme},
    std::{fs::File, io::Read, path::PathBuf},
    tracing::{info, instrument},
};

/// Prove a prepared Noir program
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "prove")]
pub struct Args {
    /// path to the compiled Noir program
    #[argh(positional)]
    scheme_path: PathBuf,

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
