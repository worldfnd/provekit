#![doc = include_str!("../README.md")]
mod compiler;
mod sparse_matrix;
mod types;
mod utils;

use {
    self::{
        compiler::R1CS, sparse_matrix::SparseMatrix, utils::file_io::deserialize_witness_stack,
    },
    acir::FieldElement,
    anyhow::{ensure, Context, Result as AnyResult},
    argh::FromArgs,
    noirc_artifacts::program::ProgramArtifact,
    std::{fs::File, path::PathBuf, vec},
    tracing_subscriber::{self, fmt::format::FmtSpan, EnvFilter},
    utils::PrintAbi,
};

/// Simple program to greet a person
#[derive(FromArgs)]
struct Args {
    #[argh(subcommand)]
    cmd: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Noir(NoirCmd),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "noir")]
/// Execute Noir VM
struct NoirCmd {
    /// path to the compiled Noir package file
    #[argh(positional)]
    program_path: PathBuf,

    /// path to the witness file
    #[argh(positional)]
    witness_path: PathBuf,
}

fn main() -> AnyResult<()> {
    tracing_subscriber::fmt()
        .with_span_events(FmtSpan::ACTIVE)
        .with_ansi(true)
        .with_env_filter(EnvFilter::from_env("PROVEKIT_LOG"))
        .init();
    let args: Args = argh::from_env();
    match args.cmd {
        Command::Noir(cmd) => noir(cmd),
    }
}

fn noir(args: NoirCmd) -> AnyResult<()> {
    println!("\nreading from args.program_path: {:?}", args.program_path);
    let file = File::open(args.program_path).context("while opening Noir program")?;
    let program: ProgramArtifact =
        serde_json::from_reader(file).context("while reading Noir program")?;

    println!("\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx program xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    println!("Program noir version: {}", program.noir_version);
    println!("Program entry point: fn main{};\n", PrintAbi(&program.abi));
    ensure!(
        program.bytecode.functions.len() == 1,
        "Program must have one entry point."
    );
    let main = &program.bytecode.functions[0];

    let mut witness_stack: acir::native_types::WitnessStack<FieldElement> =
        deserialize_witness_stack(args.witness_path.to_str().unwrap())?;

    let witness_stack = witness_stack.pop().unwrap();

    let mut r1cs = R1CS::new(main, witness_stack.witness);

    r1cs.add_circuit(main);

    Ok(())
}
