use {super::Command, anyhow::Result, argh::FromArgs, std::path::PathBuf};

/// Prove a prepared Noir program
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "prove")]
pub struct ProveArgs {
    /// path to the witness file
    #[argh(positional)]
    witness_path: PathBuf,
}

impl Command for ProveArgs {
    fn run(&self) -> Result<()> {
        todo!()
    }
}
