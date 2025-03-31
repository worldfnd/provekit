use {super::Command, anyhow::Result, argh::FromArgs, std::path::PathBuf};

/// Prepare a Noir program for proving
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "prepare")]
pub struct PrepareArgs {
    /// path to the compiled Noir program
    #[argh(positional)]
    program_path: PathBuf,

    /// output path for the prepared R1CS file
    #[argh(option)]
    output_path: PathBuf,
}

impl Command for PrepareArgs {
    fn run(&self) -> Result<()> {
        todo!()
    }
}
