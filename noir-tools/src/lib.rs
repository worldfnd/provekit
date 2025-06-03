use {
    acir::{native_types::WitnessMap, FieldElement},
    anyhow::{Context, Result},
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    nargo::foreign_calls::DefaultForeignCallBuilder,
    noir_artifact_cli::execution::execute,
    noirc_artifacts::program::ProgramArtifact,
    noirc_driver::CompiledProgram,
    std::path::Path,
};

pub fn execute_program_witness(
    program_path: impl AsRef<Path>,
    witness_path: impl AsRef<Path>,
) -> Result<WitnessMap<FieldElement>> {
    let program_file = std::fs::File::open(program_path.as_ref())?;
    let program: ProgramArtifact =
        serde_json::from_reader(program_file).context("Reading program")?;
    let program: CompiledProgram = program.into();

    let solver = Bn254BlackBoxSolver::default();
    let mut output_buffer: Vec<u8> = Vec::new();
    let mut foreign_call_executor = DefaultForeignCallBuilder {
        output:       &mut output_buffer,
        enable_mocks: false,
        resolver_url: None,
        root_path:    None,
        package_name: None,
    }
    .build();

    let mut exec_results = execute(
        &program,
        &solver,
        &mut foreign_call_executor,
        witness_path.as_ref(),
    )
    .context("Executing program")?;

    Ok(exec_results
        .witness_stack
        .pop()
        .context("Missing witness results")?
        .witness)
}
