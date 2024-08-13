mod types;
mod utils;
use clap::{Parser, ValueEnum};
use types::Program;
use utils::program_at_path;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    cmd: Command,

    /// Path to circuit file
    path: String,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Command {
    /// Compile the ACIR to R1CS
    R1CS,
}

fn main() {
    let args = Args::parse();

    match args.cmd {
        Command::R1CS => {
            let program = program_at_path(args.path);

            assert!(
                program.functions.len() == 1,
                "only one function supported at the moment",
            );
            let Program {
                mut functions,
                unconstrained_functions: _,
            } = program;
            let circuit = functions.pop().unwrap();

            println!("Opcodes : {:?}", circuit.opcodes.len());
        }
    }
}
