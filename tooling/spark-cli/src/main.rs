mod cmd;
mod span_stats;

use {anyhow::Result, argh::FromArgs};
use tracing::{instrument, subscriber};
use tracing_subscriber::{self, layer::SubscriberExt as _, Registry};
use span_stats::SpanStats;

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
