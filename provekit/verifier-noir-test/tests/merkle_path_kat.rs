//! Cross-implementation Merkle path verification KAT.
//!
//! 1. Build a 4-leaf Merkle tree in Rust via `poseidon2_hash`: leaves
//!    [[1], [2], [3], [4]], internal nodes pair-hashed up to a single root.
//! 2. Shell out to `nargo test verify_merkle_path` in the sibling Noir crate.
//!    That test runs the same path-verification through Noir's
//!    `verify_merkle_path::<1, 2>` against the frozen siblings + root.
//! 3. Passing means both implementations agree on this Merkle tree
//!    structure and path-walking convention.

use {
    provekit_verifier_noir_test::merkle_path_kat_expected,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_merkle_path_kat_agrees() {
    let a = merkle_path_kat_expected();
    let b = merkle_path_kat_expected();
    assert_eq!(a, b, "merkle_path_kat_expected non-deterministic");

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
        .args(["test", "verify_merkle_path"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo - is it on PATH?");

    assert!(
        status.success(),
        "nargo test verify_merkle_path failed (exit {:?}). \
         The Noir Merkle path walker disagreed with the Rust 4-leaf tree \
         construction on the canonical input. Re-run Phase 3A Task 2 step 2 \
         to regenerate expected values.",
        status.code(),
    );
}
