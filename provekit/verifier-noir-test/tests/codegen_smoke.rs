//! End-to-end codegen smoke test.
//!
//! Pipeline:
//!   1. `provekit-cli prepare --hash poseidon2 noir-examples/basic-2`
//!   2. `provekit-cli prove`
//!   3. `provekit-cli generate-noir-inputs`
//!   4. `nargo check` on provekit/verifier-noir
//!
//! Catches: postcard schema drift, Noir source emission bugs, type signature
//! breakage. Slow (~30s on cold cache).

use std::{env, path::PathBuf, process::Command};

/// Locate the workspace root from this crate's CARGO_MANIFEST_DIR.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("CARGO_MANIFEST_DIR has two parents")
        .to_path_buf()
}

#[test]
fn codegen_pipeline_end_to_end() {
    let root = workspace_root();
    let cli = root.join("target/release/provekit-cli");

    // Ensure the CLI binary exists (build if needed).
    if !cli.exists() {
        let status = Command::new("cargo")
            .args(["build", "-p", "provekit-cli", "--release"])
            .current_dir(&root)
            .status()
            .expect("cargo build failed to spawn");
        assert!(status.success(), "cargo build of provekit-cli failed");
    }

    let tmp = env::temp_dir().join("p2c-codegen-smoke");
    std::fs::create_dir_all(&tmp).expect("creating tmp dir");
    let pkp = tmp.join("basic2.pkp");
    let pkv = tmp.join("basic2.pkv");
    let np = tmp.join("basic2.np");

    // 1. prepare
    let status = Command::new(&cli)
        .args([
            "prepare",
            "noir-examples/basic-2",
            "--hash",
            "poseidon2",
            "--pkp",
            pkp.to_str().unwrap(),
            "--pkv",
            pkv.to_str().unwrap(),
        ])
        .current_dir(&root)
        .status()
        .expect("prepare failed to spawn");
    assert!(status.success(), "prepare failed (exit {:?})", status.code());
    assert!(pkp.exists() && pkv.exists());

    // 2. prove
    let prover_toml = root.join("noir-examples/basic-2/Prover.toml");
    let status = Command::new(&cli)
        .args([
            "prove",
            "-p",
            pkp.to_str().unwrap(),
            "-i",
            prover_toml.to_str().unwrap(),
            "-o",
            np.to_str().unwrap(),
        ])
        .current_dir(&root)
        .status()
        .expect("prove failed to spawn");
    assert!(status.success(), "prove failed (exit {:?})", status.code());
    assert!(np.exists());

    // 3. generate-noir-inputs
    let status = Command::new(&cli)
        .args([
            "generate-noir-inputs",
            pkv.to_str().unwrap(),
            np.to_str().unwrap(),
        ])
        .current_dir(&root)
        .status()
        .expect("generate-noir-inputs failed to spawn");
    assert!(
        status.success(),
        "generate-noir-inputs failed (exit {:?})",
        status.code()
    );

    // 4. nargo check on the regenerated crate
    let nargo_crate = root.join("provekit/verifier-noir");
    let status = Command::new("nargo")
        .args(["check"])
        .current_dir(&nargo_crate)
        .status()
        .expect("nargo check failed to spawn");
    assert!(
        status.success(),
        "nargo check failed (exit {:?}). \
         types.nr or matrices.nr emission produced invalid Noir source.",
        status.code()
    );
}
