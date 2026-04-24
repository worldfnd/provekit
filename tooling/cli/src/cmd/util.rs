use {
    anyhow::{Context, Result},
    nargo_toml::{find_root, get_package_manifest, resolve_workspace_from_toml, PackageSelection},
    noirc_driver::NOIR_ARTIFACT_VERSION_STRING,
    std::path::{Path, PathBuf},
};

/// Return the name of the Nargo package enclosing `dir`.
fn enclosing_package_name(dir: &Path) -> Result<String> {
    let dir =
        std::fs::canonicalize(dir).with_context(|| format!("canonicalizing {}", dir.display()))?;
    let package_dir = find_root(&dir, false)?;
    let workspace = resolve_workspace_from_toml(
        &get_package_manifest(&package_dir)?,
        PackageSelection::DefaultOrAll,
        Some(NOIR_ARTIFACT_VERSION_STRING.to_owned()),
    )?;
    let package = workspace
        .into_iter()
        .next()
        .expect("a package manifest resolves to exactly one member");
    Ok(package.name.to_string())
}

/// Resolve an optional key path, defaulting to `<circuit>.<ext>` in the current
/// directory where `<circuit>` is the enclosing Nargo package name.
pub fn resolve_key_path(path: Option<&Path>, ext: &str) -> Result<PathBuf> {
    if let Some(p) = path {
        return Ok(p.to_path_buf());
    }
    let mut path = PathBuf::from(enclosing_package_name(Path::new("."))?);
    path.set_extension(ext);
    Ok(path)
}
