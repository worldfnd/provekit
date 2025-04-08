#![doc = include_str!("../README.md")]
mod cmd;
mod compiler;
mod r1cs_matrices;
mod solver;
mod sparse_matrix;
mod utils;
mod witness;

use {
    acir::FieldElement,
    anyhow::{ensure, Context, Result as AnyResult},
    argh::FromArgs,
    compiler::R1CS,
    noirc_artifacts::program::ProgramArtifact,
    solver::MockTranscript,
    std::{fs::File, path::PathBuf},
    tracing::{info, level_filters::LevelFilter},
    tracing_subscriber::{self, fmt::format::FmtSpan, EnvFilter},
    utils::{file_io::deserialize_witness_stack, PrintAbi},
};

/// Compile a R1CS instance and R1CS solver for the compiled Noir program, solve
/// the R1CS witness values from the provided ACIR witness values, then check
/// that the R1CS instance is satisfied.
#[derive(FromArgs)]
struct Args {
    /// path to the compiled Noir program
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
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .with_env_var("PROVEKIT_LOG")
                .from_env_lossy(),
        )
        .init();
    let args: Args = argh::from_env();
    info!("Loading Noir program {:?}", args.program_path);
    let file = File::open(args.program_path).context("while opening Noir program")?;
    let program: ProgramArtifact =
        serde_json::from_reader(file).context("while reading Noir program")?;

    info!("Program noir version: {}", program.noir_version);
    info!("Program entry point: fn main{};", PrintAbi(&program.abi));
    ensure!(
        program.bytecode.functions.len() == 1,
        "Program must have one entry point."
    );
    let acir_circuit = &program.bytecode.functions[0];
    let num_acir_witnesses = acir_circuit.current_witness_index as usize;
    info!(
        "ACIR: {} witnesses, {} opcodes.",
        num_acir_witnesses,
        acir_circuit.opcodes.len()
    );

    // Compile to obtain R1CS matrices and R1CS solver
    let r1cs = R1CS::from_acir(acir_circuit);
    info!("{}", r1cs);

    // Solve for the R1CS witness using the ACIR witness
    let mut witness_stack: acir::native_types::WitnessStack<FieldElement> =
        deserialize_witness_stack(args.witness_path.to_str().unwrap())?;
    let acir_witness = witness_stack.pop().unwrap().witness;

    let mut transcript = MockTranscript::new();
    let witness = r1cs.solver.solve(&mut transcript, &acir_witness);

    // Check that the witness satisfies the R1CS relation
    if let Some(failing_constraint_idx) = r1cs.matrices.test_satisfaction(&witness) {
        return Err(anyhow::anyhow!(
            "Witness does not satisfy constraint {}",
            failing_constraint_idx
        ));
    }

    r1cs.matrices.write_json_to_file(
        acir_circuit.public_parameters.0.len(),
        &witness,
        "r1cs.json",
    )?;

    Ok(())
}
