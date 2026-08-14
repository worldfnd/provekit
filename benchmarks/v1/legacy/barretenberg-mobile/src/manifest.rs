use {
    anyhow::{bail, ensure, Context, Result},
    serde::Deserialize,
    sha2::{Digest, Sha256},
    std::{
        fs,
        path::{Component, Path, PathBuf},
    },
};

const EXPECTED_BACKEND_VERSION: &str = "0.87.0";
const EXPECTED_NOIR_VERSION: &str = "1.0.0-beta.11";
const EXPECTED_COMMIT: &str = "9081b0ed38c43c120afb7c80f8f6cd418ca5ad70";

#[derive(Debug, Deserialize)]
pub struct PackageManifest {
    pub schema_version:    u32,
    pub backend:           String,
    pub backend_version:   String,
    pub noir_version:      String,
    pub upstream_commit:   String,
    pub platform:          String,
    pub network_at_device: bool,
    pub assets:            Vec<Asset>,
}

#[derive(Debug, Deserialize)]
pub struct Asset {
    pub path:   PathBuf,
    pub role:   String,
    pub bytes:  u64,
    pub sha256: String,
}

#[derive(Debug)]
pub struct VerifiedPackage {
    pub root:     PathBuf,
    pub manifest: PackageManifest,
}

pub fn verify_package(root: impl AsRef<Path>) -> Result<VerifiedPackage> {
    verify_manifest(root.as_ref(), "package-manifest.json", true)
}

/// Verifies the runtime-only package embedded in a Mobench app.
///
/// The linked static archives are authenticated by the outer immutable
/// Mobench artifact manifest. They are deliberately not duplicated as runtime
/// resources, especially on Android where the v0.87 archive is hundreds of
/// megabytes before the final linker discards unused objects.
pub fn verify_runtime_package(root: impl AsRef<Path>) -> Result<VerifiedPackage> {
    verify_manifest(root.as_ref(), "runtime-package-manifest.json", false)
}

fn verify_manifest(
    root: &Path,
    manifest_name: &str,
    require_native_libraries: bool,
) -> Result<VerifiedPackage> {
    let manifest_path = root.join(manifest_name);
    let manifest: PackageManifest = serde_json::from_slice(
        &fs::read(&manifest_path).with_context(|| format!("read {}", manifest_path.display()))?,
    )
    .context("decode package manifest")?;
    ensure!(manifest.schema_version == 1, "unsupported manifest schema");
    ensure!(manifest.backend == "barretenberg", "unexpected backend");
    ensure!(
        manifest.backend_version == EXPECTED_BACKEND_VERSION,
        "Barretenberg version mismatch"
    );
    ensure!(
        manifest.noir_version == EXPECTED_NOIR_VERSION,
        "Noir version mismatch"
    );
    ensure!(
        manifest.upstream_commit == EXPECTED_COMMIT,
        "upstream source mismatch"
    );
    ensure!(
        !manifest.network_at_device,
        "device package must forbid network"
    );
    ensure!(
        manifest.platform == "ios" || manifest.platform == "android",
        "unsupported package platform"
    );
    ensure!(!manifest.assets.is_empty(), "package has no assets");

    let mut native_adapter_libraries = 0;
    let mut native_upstream_libraries = 0;
    let mut crs_files = 0;
    for asset in &manifest.assets {
        if asset
            .path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            bail!(
                "asset path must be relative and normalized: {:?}",
                asset.path
            );
        }
        let path = root.join(&asset.path);
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        ensure!(
            bytes.len() as u64 == asset.bytes,
            "size mismatch for {:?}",
            asset.path
        );
        let digest = hex::encode(Sha256::digest(&bytes));
        ensure!(
            digest == asset.sha256,
            "SHA-256 mismatch for {:?}",
            asset.path
        );
        if asset.role == "native-adapter-library" {
            native_adapter_libraries += 1;
        } else if asset.role == "native-upstream-library" {
            native_upstream_libraries += 1;
        } else if asset.role == "crs" {
            crs_files += 1;
        }
    }
    if require_native_libraries {
        ensure!(
            native_adapter_libraries == 1,
            "package must contain one native adapter library"
        );
        ensure!(
            native_upstream_libraries == 1,
            "package must contain one native upstream library"
        );
    } else {
        ensure!(
            native_adapter_libraries == 0 && native_upstream_libraries == 0,
            "runtime package must not duplicate linked static archives"
        );
    }
    ensure!(crs_files > 0, "package must contain a local CRS");
    for crs_name in ["bn254_g1.dat", "bn254_g2.dat"] {
        let crs_path = Path::new("crs").join(crs_name);
        ensure!(
            manifest
                .assets
                .iter()
                .any(|asset| asset.role == "crs" && asset.path == crs_path),
            "package is missing {crs_name}"
        );
    }
    for workload in [
        "passport_complete_age_check",
        "webauthn_assertion",
        "oprf_taceo",
    ] {
        let fixture_role = format!("fixture:{workload}");
        ensure!(
            manifest
                .assets
                .iter()
                .filter(|asset| asset.role == fixture_role)
                .count()
                == 4,
            "package has an incomplete {workload} frozen fixture"
        );
        for suffix in ["native-bytecode", "native-public-inputs"] {
            let role = format!("fixture:{workload}:{suffix}");
            ensure!(
                manifest
                    .assets
                    .iter()
                    .filter(|asset| asset.role == role)
                    .count()
                    == 1,
                "package has an incomplete {workload} native fixture"
            );
        }
    }
    Ok(VerifiedPackage {
        root: root.to_path_buf(),
        manifest,
    })
}

#[cfg(test)]
mod tests {
    use {super::*, serde_json::json};

    fn write_asset(root: &Path, path: &str, role: &str) -> serde_json::Value {
        let bytes = format!("{path}:{role}").into_bytes();
        let destination = root.join(path);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&destination, &bytes).unwrap();
        json!({
            "path": path,
            "role": role,
            "bytes": bytes.len(),
            "sha256": hex::encode(Sha256::digest(&bytes)),
        })
    }

    #[test]
    fn rejects_wrong_version_before_reading_assets() {
        let root =
            std::env::temp_dir().join(format!("bb-v087-manifest-test-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("package-manifest.json"),
            r#"{
              "schema_version":1,"backend":"barretenberg",
              "backend_version":"4.2.0","noir_version":"1.0.0-beta.19",
              "upstream_commit":"wrong","platform":"ios",
              "network_at_device":false,"assets":[]
            }"#,
        )
        .unwrap();
        let error = verify_package(&root).unwrap_err().to_string();
        assert!(error.contains("Barretenberg version mismatch"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepts_complete_package_and_rejects_tampering() {
        let root = std::env::temp_dir().join(format!("bb-v087-valid-test-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let mut assets = vec![
            write_asset(
                &root,
                "lib/libbarretenberg_v087_mobile.a",
                "native-adapter-library",
            ),
            write_asset(&root, "lib/libbarretenberg.a", "native-upstream-library"),
            write_asset(&root, "crs/bn254_g1.dat", "crs"),
            write_asset(&root, "crs/bn254_g2.dat", "crs"),
        ];
        for workload in [
            "passport_complete_age_check",
            "webauthn_assertion",
            "oprf_taceo",
        ] {
            for name in [
                "circuit.json",
                "witness.gz",
                "public-inputs.json",
                "proof.bin",
            ] {
                assets.push(write_asset(
                    &root,
                    &format!("fixtures/{workload}/{name}"),
                    &format!("fixture:{workload}"),
                ));
            }
            for (name, suffix) in [
                ("bytecode.gz", "native-bytecode"),
                ("public_inputs", "native-public-inputs"),
            ] {
                assets.push(write_asset(
                    &root,
                    &format!("fixtures/{workload}/{name}"),
                    &format!("fixture:{workload}:{suffix}"),
                ));
            }
        }
        let manifest = json!({
            "schema_version": 1,
            "backend": "barretenberg",
            "backend_version": EXPECTED_BACKEND_VERSION,
            "noir_version": EXPECTED_NOIR_VERSION,
            "upstream_commit": EXPECTED_COMMIT,
            "platform": "ios",
            "network_at_device": false,
            "assets": assets,
        });
        fs::write(
            root.join("package-manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        verify_package(&root).unwrap();

        fs::write(root.join("crs/bn254_g2.dat"), b"tampered").unwrap();
        assert!(verify_package(&root)
            .unwrap_err()
            .to_string()
            .contains("mismatch"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepts_runtime_package_without_duplicating_linked_archives() {
        let root =
            std::env::temp_dir().join(format!("bb-v087-runtime-test-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let mut assets = vec![
            write_asset(&root, "crs/bn254_g1.dat", "crs"),
            write_asset(&root, "crs/bn254_g2.dat", "crs"),
        ];
        for workload in [
            "passport_complete_age_check",
            "webauthn_assertion",
            "oprf_taceo",
        ] {
            for name in [
                "circuit.json",
                "witness.gz",
                "public-inputs.json",
                "proof.bin",
            ] {
                assets.push(write_asset(
                    &root,
                    &format!("fixtures/{workload}/{name}"),
                    &format!("fixture:{workload}"),
                ));
            }
            for (name, suffix) in [
                ("bytecode.gz", "native-bytecode"),
                ("public_inputs", "native-public-inputs"),
            ] {
                assets.push(write_asset(
                    &root,
                    &format!("fixtures/{workload}/{name}"),
                    &format!("fixture:{workload}:{suffix}"),
                ));
            }
        }
        let manifest = json!({
            "schema_version": 1,
            "backend": "barretenberg",
            "backend_version": EXPECTED_BACKEND_VERSION,
            "noir_version": EXPECTED_NOIR_VERSION,
            "upstream_commit": EXPECTED_COMMIT,
            "platform": "android",
            "network_at_device": false,
            "assets": assets,
        });
        fs::write(
            root.join("runtime-package-manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        verify_runtime_package(&root).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
