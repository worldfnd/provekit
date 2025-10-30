//! ACIR circuit statistics analyzer.
//!
//! This module provides comprehensive analysis of ACIR circuits, including:
//! - Constraint and witness counts
//! - Black box function usage
//! - Memory operation statistics
//! - Range check analysis
//! - Exact R1CS compilation results

mod display;
mod memory;
mod stats_collector;

use {
    super::Command,
    acir::{circuit::Program, FieldElement},
    anyhow::{Context, Result},
    argh::FromArgs,
    base64::Engine,
    provekit_r1cs_compiler::noir_to_r1cs,
    stats_collector::CircuitStats,
    std::{fs, path::PathBuf},
    tracing::instrument,
};

/// Analyzes ACIR circuit statistics and R1CS complexity.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "circuit_stats")]
pub struct Args {
    /// path to the ACIR circuit file (.json)
    #[argh(positional)]
    circuit_path: PathBuf,

    /// path to witness file (reserved for future use)
    #[argh(positional)]
    witness_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let program = load_program(&self.circuit_path)?;
        analyze_circuit(program, &self.circuit_path)
    }
}

/// Loads and deserializes an ACIR program from a JSON file.
fn load_program(path: &PathBuf) -> Result<Program<FieldElement>> {
    let json_string = fs::read_to_string(path)
        .with_context(|| format!("Failed to read circuit file: {}", path.display()))?;

    let json: serde_json::Value =
        serde_json::from_str(&json_string).context("Failed to parse circuit JSON")?;

    let bytecode_str = json["bytecode"]
        .as_str()
        .context("Expected 'bytecode' field in circuit JSON")?;

    let bytecode = base64::prelude::BASE64_STANDARD
        .decode(bytecode_str)
        .context("Failed to decode base64 bytecode")?;

    Program::deserialize_program(&bytecode).context("Failed to deserialize ACIR program")
}

/// Analyzes a circuit and displays comprehensive statistics.
fn analyze_circuit(program: Program<FieldElement>, path: &PathBuf) -> Result<()> {
    anyhow::ensure!(
        program.functions.len() == 1,
        "Only single-function programs are currently supported (found {} functions)",
        program.functions.len()
    );

    let Program {
        mut functions,
        unconstrained_functions: _,
    } = program;
    let circuit = functions.pop().unwrap();

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║                   ACIR Circuit Analysis                       ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!("Circuit: {}", path.display());

    // Display circuit I/O summary
    display::print_io_summary(&circuit);

    // Collect statistics from ACIR opcodes
    let stats = CircuitStats::from_circuit(&circuit);

    // Display ACIR-level statistics
    display::print_acir_stats(&stats);

    // Compile to R1CS for exact complexity analysis
    let (r1cs, _witness_map, _witness_builders, breakdown) =
        noir_to_r1cs(&circuit).context("Failed to compile circuit to R1CS")?;

    // Display R1CS complexity breakdown
    display::print_r1cs_breakdown(&stats, &circuit, &r1cs, &breakdown);

    Ok(())
}
