mod display;
mod memory;
mod stats_collector;

use {
    super::Command,
    acir::{circuit::Program, FieldElement},
    anyhow::{Context, Result},
    argh::FromArgs,
    base64::Engine,
    provekit_r1cs_compiler::noir_to_r1cs_with_breakdown,
    stats_collector::CircuitStats,
    std::{
        fs,
        path::{Path, PathBuf},
    },
    tracing::instrument,
};

#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(
    subcommand,
    name = "circuit_stats",
    description = "analyze ACIR circuit statistics and R1CS complexity"
)]
pub struct Args {
    #[argh(positional, description = "path to the ACIR circuit file (.json)")]
    circuit_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let program = load_program(&self.circuit_path)?;
        analyze_circuit(program, &self.circuit_path)
    }
}

fn load_program(path: &Path) -> Result<Program<FieldElement>> {
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

fn analyze_circuit(program: Program<FieldElement>, path: &Path) -> Result<()> {
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

    display::print_io_summary(&circuit);

    let stats = CircuitStats::from_circuit(&circuit);

    display::print_acir_stats(&stats);

    let (r1cs, _witness_map, _witness_builders, breakdown) =
        noir_to_r1cs_with_breakdown(&circuit).context("Failed to compile circuit to R1CS")?;

    display::print_r1cs_breakdown(&stats, &circuit, &r1cs, &breakdown);

    Ok(())
}
