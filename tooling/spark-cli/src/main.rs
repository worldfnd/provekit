mod cmd;

use ::{anyhow::Result, argh::FromArgs};

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

    match args.command {
        Command::Prove(args) => cmd::prove::execute(args),
        Command::Verify(args) => cmd::verify::execute(args),
    }
}
