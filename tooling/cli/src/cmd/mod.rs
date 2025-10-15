mod circuit_stats;
mod generate_gnark_inputs;
mod prepare;
mod prove;
mod verify;

use {anyhow::Result, argh::FromArgs};

pub trait Command {
    fn run(&self) -> Result<()>;
}

/// Prove & verify a compiled Noir program using R1CS.
#[derive(FromArgs, PartialEq, Debug)]
pub struct Args {
    #[argh(subcommand)]
    subcommand: Commands,

    /// enable Tracy profiling
    #[cfg(feature = "tracy")]
    #[argh(switch)]
    pub tracy: bool,

    /// enable Tracy allocation tracking with provided stack depth, or 0 to
    /// trace allocations without stack traces.
    #[cfg(feature = "tracy")]
    #[argh(option)]
    pub tracy_allocations: Option<usize>,

    /// keep the process alive after completion to allow tracy to collect data
    #[cfg(feature = "tracy")]
    #[argh(switch)]
    pub tracy_keepalive: bool,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum Commands {
    Prepare(prepare::Args),
    Prove(prove::Args),
    CircuitStats(circuit_stats::Args),
    Verify(verify::Args),
    GenerateGnarkInputs(generate_gnark_inputs::Args),
}

impl Command for Args {
    fn run(&self) -> Result<()> {
        self.subcommand.run()
    }
}

impl Command for Commands {
    fn run(&self) -> Result<()> {
        match self {
            Self::Prepare(args) => args.run(),
            Self::Prove(args) => args.run(),
            Self::CircuitStats(args) => args.run(),
            Self::Verify(args) => args.run(),
            Self::GenerateGnarkInputs(args) => args.run(),
        }
    }
}
