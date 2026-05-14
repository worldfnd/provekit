mod analyze_pkp;
mod circuit_stats;
mod generate_gnark_inputs;
pub mod prepare;
mod prove;
mod prove_spark;
mod show_inputs;
mod util;
mod verify;
mod verify_spark;

use {anyhow::Result, argh::FromArgs};

pub trait Command {
    fn run(&self) -> Result<()>;
}

/// Compile, prove, and verify Noir programs using R1CS.
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
    AnalyzePkp(analyze_pkp::Args),
    Prepare(prepare::Args),
    Prove(prove::Args),
    ProveSpark(prove_spark::Args),
    CircuitStats(circuit_stats::Args),
    Verify(verify::Args),
    VerifySpark(verify_spark::Args),
    GenerateGnarkInputs(generate_gnark_inputs::Args),
    ShowInputs(show_inputs::Args),
}

impl Command for Args {
    fn run(&self) -> Result<()> {
        self.subcommand.run()
    }
}

impl Command for Commands {
    fn run(&self) -> Result<()> {
        match self {
            Self::AnalyzePkp(args) => args.run(),
            Self::Prepare(args) => args.run(),
            Self::Prove(args) => args.run(),
            Self::ProveSpark(args) => args.run(),
            Self::CircuitStats(args) => args.run(),
            Self::Verify(args) => args.run(),
            Self::VerifySpark(args) => args.run(),
            Self::GenerateGnarkInputs(args) => args.run(),
            Self::ShowInputs(args) => args.run(),
        }
    }
}
