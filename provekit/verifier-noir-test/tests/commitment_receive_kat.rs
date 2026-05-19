//! Cross-impl commitment receive KAT.

use {
    provekit_verifier_noir_test::commitment_receive_kat_expected,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_commitment_receive_kat_agrees() {
    let a = commitment_receive_kat_expected();
    let b = commitment_receive_kat_expected();
    assert_eq!(a, b, "commitment_receive_kat_expected non-deterministic");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let nargo_crate = manifest_dir
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .join("verifier-noir");
    assert!(nargo_crate.join("Nargo.toml").exists());

    let status = Command::new("nargo")
        .args(["test", "receive_commitment_matches_frozen_kat"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo");

    assert!(
        status.success(),
        "nargo test receive_commitment_matches_frozen_kat failed (exit {:?})",
        status.code(),
    );
}
