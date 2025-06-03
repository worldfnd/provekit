use {
    acir::{native_types::WitnessMap, FieldElement},
    anyhow::{Context, Result},
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    nargo::{foreign_calls::DefaultForeignCallBuilder, workspace::Workspace},
    nargo_cli::cli::compile_cmd::compile_workspace_full,
    nargo_toml::{resolve_workspace_from_toml, PackageSelection},
    noir_artifact_cli::execution::execute,
    noirc_artifacts::program::ProgramArtifact,
    noirc_driver::{CompileOptions, CompiledProgram},
    std::path::Path,
};

pub fn compile_workspace(workspace_path: impl AsRef<Path>) -> Result<Workspace> {
    let workspace_path = workspace_path.as_ref();
    let workspace_path = if workspace_path.ends_with("Nargo.toml") {
        workspace_path.to_owned()
    } else {
        workspace_path.join("Nargo.toml")
    };

    // `resolve_workspace_from_toml` calls .normalize() under the hood which messes
    // up path resolution
    let workspace_path = workspace_path.canonicalize()?;

    let workspace =
        resolve_workspace_from_toml(&workspace_path, PackageSelection::DefaultOrAll, None)?;
    let compile_options = CompileOptions::default();

    compile_workspace_full(&workspace, &compile_options, None)?;

    Ok(workspace)
}

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
