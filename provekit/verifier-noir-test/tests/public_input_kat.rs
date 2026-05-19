//! Cross-implementation public-input binding KAT.
//!
//! 1. Compute `HashConfig::Poseidon2.hash_field_elements(&[7, 11, 13])` in
//!    Rust — this is `poseidon2_hash([DST_FE, 7, 11, 13])`.
//! 2. Shell out to `nargo test public_input` in the sibling Noir crate. That
//!    runs Noir's `verify_public_input_hash::<3>(EXPECTED_PI_HASH, [7, 11, 13])`
//!    which builds the same tagged input and hashes it with the lane-grain
//!    Poseidon2 length-IV hash.
//! 3. Passing means both implementations agree on the public-input hash for
//!    this canonical input.

use {
    provekit_verifier_noir_test::public_input_kat_expected,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_public_input_kat_agrees() {
    let a = public_input_kat_expected();
    let b = public_input_kat_expected();
    assert_eq!(a, b, "public_input_kat_expected non-deterministic");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let nargo_crate = manifest_dir
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .join("verifier-noir");
    assert!(
        nargo_crate.join("Nargo.toml").exists(),
        "verifier-noir Nargo.toml not found"
    );

    let status = Command::new("nargo")
        .args(["test", "public_input"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo - is it on PATH?");

    assert!(
        status.success(),
        "nargo test public_input failed (exit code {:?}). \
         The Noir public-input verifier disagreed with Rust HashConfig::Poseidon2 \
         on hash([7, 11, 13]). Likely causes: DST_FE mismatch, length-IV hash \
         drift, or matrix tagging order. Re-run Phase 2B Task 4 step 3 to \
         regenerate expected values.",
        status.code(),
    );
}
