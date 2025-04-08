use {
    super::Command,
    crate::write,
    anyhow::{Context, Result},
    argh::FromArgs,
    noir_r1cs::NoirProofScheme,
    postcard,
    std::{fs::File, io::Write, path::PathBuf},
    tracing::{info, instrument},
    zstd::stream::Encoder as ZstdEncoder,
};

/// Prepare a Noir program for proving
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "prepare")]
pub struct PrepareArgs {
    /// path to the compiled Noir program
    #[argh(positional)]
    program_path: PathBuf,

    /// output path for the prepared proof scheme
    #[argh(option, default = "PathBuf::from(\"noir_proof_scheme.bin\")")]
    output_path: PathBuf,
}

impl Command for PrepareArgs {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let scheme = NoirProofScheme::from_file(&self.program_path)
            .context("while compiling Noir program")?;

        // Store to file.
        write(&scheme, &self.output_path).context("while writing Noir proof scheme")?;

        Ok(())
    }
}
