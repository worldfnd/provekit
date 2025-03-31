use {
    crate::utils::PrintAbi,
    anyhow::{ensure, Context as _, Result},
    noirc_artifacts::program::ProgramArtifact,
    serde_json::from_reader,
    std::{fs::File, path::Path},
    tracing::{info, instrument},
};

#[instrument(fields(size = program_path.metadata().map(|m| m.len()).ok()))]
pub fn load_noir_program(program_path: &Path) -> Result<ProgramArtifact> {
    let file = File::open(program_path).context("while opening Noir program")?;
    let program: ProgramArtifact = from_reader(file).context("while reading Noir program")?;

    info!("Program noir version: {}", program.noir_version);
    info!("Program entry point: fn main{};", PrintAbi(&program.abi));
    ensure!(
        program.bytecode.functions.len() == 1,
        "Program must have one entry point."
    );

    Ok(program)
}
