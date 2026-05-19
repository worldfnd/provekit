//! Cross-impl `geometric_challenge` KAT.

use {
    provekit_verifier_noir_test::geometric_challenge_kat_expected,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_geometric_challenge_kat_agrees() {
    let a = geometric_challenge_kat_expected();
    let b = geometric_challenge_kat_expected();
    assert_eq!(a, b, "geometric_challenge_kat_expected non-deterministic");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let nargo_crate = manifest_dir
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .join("verifier-noir");
    assert!(nargo_crate.join("Nargo.toml").exists());

    let status = Command::new("nargo")
        .args(["test", "geometric_challenge"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo");

    assert!(
        status.success(),
        "nargo test geometric_challenge failed (exit {:?})",
        status.code(),
    );
}
