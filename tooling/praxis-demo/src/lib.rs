//! Praxis 100-bit Witness Encryption + ProveKit library.
//!
//! Supports two complementary ProveKit -> Praxis architectures:
//! - [`direct`]: Noir -> ProveKit `R1CS<Fr>` -> Praxis `Bqs` -> 100-bit Praxis
//!   WE (best for small challenge-free circuits, e.g. `praxis-satoshi` at ~36
//!   MiB).
//! - [`kzg`]: Noir -> ProveKit 2-round `Spartan + HyperKZG` (universal BN254
//!   Powers-of-Tau SRS, **2 pairings**, zero Groth16 / zero gnark) -> Praxis
//!   100-bit WE (works on arbitrary multi-challenge circuits like `t_attest`
//!   and `complete_age_check` with constant ~7.5–9 GiB verifier BQS).

pub mod bqs;
pub mod direct;
pub mod ext;
pub mod kzg;
pub mod params;
pub mod praxis;
pub mod qap;
pub mod search;

use {
    anyhow::{ensure, Context, Result},
    nargo_cli::cli::compile_cmd::compile_workspace_full,
    nargo_toml::{resolve_workspace_from_toml, PackageSelection},
    noirc_artifacts::program::ProgramArtifact,
    noirc_driver::CompileOptions,
    std::{
        fs::File,
        path::{Path, PathBuf},
    },
};

/// Load a Noir `ProgramArtifact` either directly from a compiled `.json`
/// artifact path or by compiling a Noir circuit directory containing
/// `Nargo.toml` using the embedded `nargo_cli`.
pub fn load_or_compile_noir(circuit_path: &Path) -> Result<ProgramArtifact> {
    if circuit_path.is_file() && circuit_path.extension().is_some_and(|e| e == "json") {
        let program: ProgramArtifact = serde_json::from_reader(
            File::open(circuit_path)
                .with_context(|| format!("opening artifact {}", circuit_path.display()))?,
        )?;
        return Ok(program);
    }

    let toml_path = circuit_path
        .join("Nargo.toml")
        .canonicalize()
        .with_context(|| format!("missing Nargo.toml in {}", circuit_path.display()))?;
    let workspace = resolve_workspace_from_toml(&toml_path, PackageSelection::DefaultOrAll, None)?;
    let pkg = workspace
        .members
        .first()
        .context("Noir workspace has no packages")?;

    // Prefer already-compiled artifact in `<dir>/target/<pkg>.json` or
    // `<workspace_root>/target/<pkg>.json` if present (avoids recompiling
    // vendored passport circuits when target JSON already exists).
    let local_artifact = circuit_path.join(format!("target/{}.json", pkg.name));
    let ws_artifact = workspace
        .root_dir
        .join(format!("target/{}.json", pkg.name));
    let artifact_path: PathBuf = if local_artifact.exists() {
        local_artifact
    } else if ws_artifact.exists() {
        ws_artifact
    } else {
        compile_workspace_full(&workspace, &CompileOptions::default(), None)?;
        ensure!(
            local_artifact.exists() || ws_artifact.exists(),
            "compiled artifact not found at {} or {}",
            local_artifact.display(),
            ws_artifact.display()
        );
        if local_artifact.exists() {
            local_artifact
        } else {
            ws_artifact
        }
    };

    let program: ProgramArtifact = serde_json::from_reader(File::open(&artifact_path)?)?;
    Ok(program)
}
