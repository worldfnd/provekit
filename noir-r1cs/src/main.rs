#![doc = include_str!("../README.md")]
mod compiler;
mod sparse_matrix;
mod utils;
mod solver;
mod r1cs_matrices;

use {
    acir::{native_types::Witness as AcirWitness, FieldElement}, anyhow::{ensure, Context, Result as AnyResult}, argh::FromArgs, compiler::R1CS, noirc_artifacts::program::ProgramArtifact, solver::MockTranscript, std::{fs::File, path::PathBuf}, tracing::{info, level_filters::LevelFilter}, tracing_subscriber::{self, fmt::format::FmtSpan, EnvFilter}, utils::{file_io::deserialize_witness_stack, PrintAbi}
};

/// Prove & verify a compiled Noir program using R1CS.
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
    prove_verify(args)
}

fn prove_verify(args: Args) -> AnyResult<()> {
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
    let main = &program.bytecode.functions[0];
    let num_public_parameters = main.public_parameters.0.len();
    let num_acir_witnesses = main.current_witness_index as usize;
    info!(
        "ACIR: {} witnesses, {} opcodes.",
        num_acir_witnesses,
        main.opcodes.len()
    );

    let mut witness_stack: acir::native_types::WitnessStack<FieldElement> =
        deserialize_witness_stack(args.witness_path.to_str().unwrap())?;

    let acir_witness = witness_stack.pop().unwrap().witness;

    if num_acir_witnesses < 15 {
        println!("ACIR witness values:");
        (0..num_acir_witnesses).for_each(|i| {
            println!("{}: {:?}", i, acir_witness[&AcirWitness(i as u32)]);
        });
    }

    // Determine the R1CS constraints and witnesses from the ACIR program
    let r1cs = R1CS::from_acir(main);
    print!("{}", r1cs);

    // Solve for the R1CS witness using the ACIR witness
    let mut transcript = MockTranscript::new();
    let witness = r1cs.solver.solve(&mut transcript, &acir_witness);

    // Check that the witness satisfies the R1CS relation
    if let Some(failing_constraint_idx) = r1cs.matrices.test_satisfaction(&witness) {
        return Err(anyhow::anyhow!(
            "Witness does not satisfy constraint {}",
            failing_constraint_idx
        ));
    }

    r1cs.matrices.write_json_to_file(num_public_parameters, &witness, "r1cs.json")?;

    Ok(())
}