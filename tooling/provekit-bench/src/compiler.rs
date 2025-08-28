//! Noir workspace compilation utilities for benchmarking and testing

use {
    anyhow::{Context, Result},
    nargo_cli::cli::compile_cmd::compile_workspace_full,
    nargo_toml::{resolve_workspace_from_toml, PackageSelection},
    noirc_driver::CompileOptions,
    provekit_common::NoirProofScheme,
    provekit_r1cs_compiler::NoirProofSchemeBuilder,
    serde::Deserialize,
    std::path::Path,
};

#[derive(Debug, Deserialize)]
pub struct NargoToml {
    pub package: NargoTomlPackage,
}

#[derive(Debug, Deserialize)]
pub struct NargoTomlPackage {
    pub name: String,
}

/// Compile a Noir workspace if the target directory doesn't exist or is empty
pub fn ensure_compiled(workspace_path: impl AsRef<Path>) -> Result<()> {
    let workspace_path = workspace_path.as_ref();
    let nargo_toml_path = if workspace_path.ends_with("Nargo.toml") {
        workspace_path.to_owned()
    } else {
        workspace_path.join("Nargo.toml")
    };

    // Check if target directory exists and has content
    let target_dir = workspace_path
        .parent()
        .unwrap_or(workspace_path)
        .join("target");

    if target_dir.exists() && target_dir.read_dir()?.next().is_some() {
        return Ok(()); // Already compiled
    }

    compile_noir_workspace(&nargo_toml_path)
}

/// Force compile a Noir workspace
pub fn compile_noir_workspace(nargo_toml_path: impl AsRef<Path>) -> Result<()> {
    let nargo_toml_path_ref = nargo_toml_path.as_ref();
    let nargo_toml_path = nargo_toml_path_ref.canonicalize().with_context(|| {
        format!(
            "Failed to canonicalize path: {}",
            nargo_toml_path_ref.display()
        )
    })?;

    let workspace =
        resolve_workspace_from_toml(&nargo_toml_path, PackageSelection::DefaultOrAll, None)
            .with_context(|| {
                format!(
                    "Failed to resolve workspace from {}",
                    nargo_toml_path.display()
                )
            })?;

    let compile_options = CompileOptions::default();
    compile_workspace_full(&workspace, &compile_options, None).with_context(|| {
        format!(
            "Failed to compile workspace at {}",
            nargo_toml_path.display()
        )
    })?;

    Ok(())
}

/// Load a NoirProofScheme from a compiled JSON artifact with helpful error
/// messaging
pub fn load_scheme_from_artifact(artifact_path: impl AsRef<Path>) -> Result<NoirProofScheme> {
    let artifact_path = artifact_path.as_ref();

    if !artifact_path.exists() {
        return Err(anyhow::anyhow!(
            "Compiled artifact not found at {}. Run 'nargo compile' in the Noir project directory \
             to generate the required artifacts.",
            artifact_path.display()
        ));
    }

    NoirProofScheme::from_file(artifact_path)
        .with_context(|| format!("Failed to load scheme from {}", artifact_path.display()))
}

/// Get the package name from a Nargo.toml file
pub fn get_package_name(nargo_toml_path: impl AsRef<Path>) -> Result<String> {
    let content = std::fs::read_to_string(nargo_toml_path.as_ref())
        .with_context(|| format!("Failed to read {}", nargo_toml_path.as_ref().display()))?;

    let nargo_toml: NargoToml = toml::from_str(&content)
        .with_context(|| format!("Failed to parse {}", nargo_toml_path.as_ref().display()))?;

    Ok(nargo_toml.package.name)
}

/// Compile a Noir project and return the path to the compiled JSON artifact
pub fn compile_and_get_artifact_path(project_path: impl AsRef<Path>) -> Result<std::path::PathBuf> {
    let project_path = project_path.as_ref();

    // Ensure the project is compiled
    ensure_compiled(project_path)?;

    // Get the package name
    let nargo_toml_path = project_path.join("Nargo.toml");
    let package_name = get_package_name(&nargo_toml_path)?;

    // Return the artifact path
    let artifact_path = project_path.join(format!("target/{}.json", package_name));

    if !artifact_path.exists() {
        return Err(anyhow::anyhow!(
            "Compiled artifact not found at {} after compilation. Check that the compilation \
             succeeded.",
            artifact_path.display()
        ));
    }

    Ok(artifact_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_name_parsing() {
        let toml_content = r#"
[package]
name = "test_package"
type = "bin"
authors = [""]
compiler_version = ">=0.1.0"

[dependencies]
"#;

        let temp_file = std::env::temp_dir().join("test_Nargo.toml");
        std::fs::write(&temp_file, toml_content).unwrap();

        let package_name = get_package_name(&temp_file).unwrap();
        assert_eq!(package_name, "test_package");

        std::fs::remove_file(temp_file).unwrap();
    }
}
