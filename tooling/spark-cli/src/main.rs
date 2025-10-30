#![allow(missing_docs)]
mod cmd;
#[cfg(feature = "profiling-allocator")]
mod profiling_alloc;
mod span_stats;

#[cfg(feature = "profiling-allocator")]
use crate::profiling_alloc::ProfilingAllocator;

#[cfg(feature = "profiling-allocator")]
#[global_allocator]
static ALLOCATOR: ProfilingAllocator = ProfilingAllocator::new();

use {
    anyhow::Result,
    argh::FromArgs,
    span_stats::SpanStats,
    tracing::{instrument, subscriber},
    tracing_subscriber::{self, layer::SubscriberExt as _, Registry},
};

#[derive(FromArgs)]
#[argh(description = "SPARK Prover CLI")]
struct Args {
    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Prove(cmd::prove::ProveArgs),
    Verify(cmd::verify::VerifyArgs),
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();
    let subscriber = Registry::default().with(SpanStats);
    subscriber::set_global_default(subscriber)?;

    match args.command {
        Command::Prove(args) => cmd::prove::execute(args),
        Command::Verify(args) => cmd::verify::execute(args),
    }
}
