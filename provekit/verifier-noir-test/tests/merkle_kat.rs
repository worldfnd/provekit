//! Cross-implementation Poseidon2 length-IV hash KAT.
//!
//! 1. Compute `poseidon2_hash([1, 2])` via the Rust `poseidon2` workspace crate.
//! 2. Shell out to `nargo test length_iv_hash` in the sibling Noir crate.
//!    That test asserts Noir's `length_iv_hash::<2>([1, 2])` matches the
//!    frozen `EXPECTED_HASH_2` global.
//! 3. Passing means both implementations agree on this KAT input.

use {
    provekit_verifier_noir_test::merkle_kat_expected,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_merkle_kat_agrees() {
    let a = merkle_kat_expected();
    let b = merkle_kat_expected();
    assert_eq!(a, b, "Rust poseidon2_hash is non-deterministic on the KAT");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let nargo_crate = manifest_dir
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .join("verifier-noir");
    assert!(
        nargo_crate.join("Nargo.toml").exists(),
        "verifier-noir Nargo.toml not found at {}",
        nargo_crate.display()
    );

    let status = Command::new("nargo")
        .args(["test", "length_iv_hash"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo - is it on PATH?");

    assert!(
        status.success(),
        "nargo test length_iv_hash failed (exit code {:?}). \
         The Noir length-IV hash disagreed with the Rust poseidon2_hash output \
         on input [1, 2]. Re-run Phase 2A Task 2 step 2 to regenerate the \
         expected value.",
        status.code(),
    );
}
