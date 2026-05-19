//! Cross-impl PoW KAT: the Rust helper and the frozen Noir constants must agree.

use {
    provekit_verifier_noir_test::pow_kat_expected,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_pow_kat_agrees() {
    // Confirm determinism: two calls must return the same nonce.
    let a = pow_kat_expected();
    let b = pow_kat_expected();
    assert_eq!(a, b, "pow_kat_expected is non-deterministic");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let nargo_crate = manifest_dir
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .join("verifier-noir");
    assert!(
        nargo_crate.join("Nargo.toml").exists(),
        "verifier-noir Nargo.toml not found at {:?}",
        nargo_crate
    );

    let status = Command::new("nargo")
        .args(["test", "verify_pow_matches_frozen_kat"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo");

    assert!(
        status.success(),
        "nargo test verify_pow_matches_frozen_kat failed (exit {:?})",
        status.code(),
    );
}
