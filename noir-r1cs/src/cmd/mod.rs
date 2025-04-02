mod circuit_stats;
mod prepare;
mod prove;
pub(self) mod utils;

use {anyhow::Result, argh::FromArgs};

pub trait Command {
    fn run(&self) -> Result<()>;
}

/// Prove & verify a compiled Noir program using R1CS.
#[derive(FromArgs, PartialEq, Debug)]
pub struct Args {
    #[argh(subcommand)]
    subcommand: Commands,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum Commands {
    Prepare(prepare::PrepareArgs),
    Prove(prove::ProveArgs),
    CircuitStats(circuit_stats::Args),
    // TODO: Verify
}

impl Command for Args {
    fn run(&self) -> Result<()> {
        self.subcommand.run()
    }
}

impl Command for Commands {
    fn run(&self) -> Result<()> {
        match self {
            Commands::Prepare(args) => args.run(),
            Commands::Prove(args) => args.run(),
            Commands::CircuitStats(args) => args.run(),
        }
    }
}
