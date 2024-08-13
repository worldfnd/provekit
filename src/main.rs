use clap::{Parser, ValueEnum};
use std::fs;

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
            let contents =
                fs::read_to_string(args.path).expect("Should have been able to read the file");

            println!("With text:\n{contents}");
        }
    }
}
