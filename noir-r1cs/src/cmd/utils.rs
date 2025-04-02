use {
    anyhow::{ensure, Context as _, Result},
    noir_r1cs::utils::PrintAbi,
    noirc_artifacts::program::ProgramArtifact,
    serde_json::from_reader,
    std::{fs::File, path::Path},
    tracing::{info, instrument},
};

#[instrument(fields(size = program_path.metadata().map(|m| m.len()).ok()))]
pub fn load_noir_program(program_path: &Path) -> Result<ProgramArtifact> {
    let file = File::open(program_path).context("while opening Noir program")?;
    let program: ProgramArtifact = from_reader(file).context("while reading Noir program")?;

    Ok(program)
}
