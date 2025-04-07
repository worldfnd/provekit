use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    noir_r1cs::NoirProofScheme,
    postcard,
    std::{fs::File, path::PathBuf},
    tracing::instrument,
};

/// Prepare a Noir program for proving
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "prepare")]
pub struct PrepareArgs {
    /// path to the compiled Noir program
    #[argh(positional)]
    program_path: PathBuf,

    /// output path for the prepared R1CS file
    #[argh(option, default = "PathBuf::from(\"r1cs.json\")")]
    output_path: PathBuf,
}

impl Command for PrepareArgs {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let scheme = NoirProofScheme::from_file(&self.program_path)
            .context("while compiling Noir program")?;

        // Store to file.
        let mut file = File::create(&self.output_path).context("while creating output file")?;
        postcard::to_io(&scheme, &mut file).context("while writing Noir proof scheme")?;

        Ok(())
    }
}
