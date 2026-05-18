//! Cross-implementation Poseidon2 KAT.
//!
//! 1. Compute the Poseidon2 permutation output for a fixed `[Fr; 4]` input
//!    via the Rust `poseidon2` workspace crate.
//! 2. Shell out to `nargo test poseidon2` in the sibling Noir crate.
//!    That test asserts the stdlib permutation produces the same four
//!    field elements (frozen as Noir `global` constants in `poseidon2.nr`).
//! 3. Passing means both implementations agree on this KAT input.

use {
    provekit_verifier_noir_test::{kat_expected, kat_input},
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_kat_agrees() {
    // Sanity: Rust side computes a deterministic output.
    let a = kat_expected();
    let b = poseidon2::permutation::poseidon2_permutation(&kat_input());
    assert_eq!(a, b, "Rust poseidon2 crate is non-deterministic on the KAT input");

    // Locate the verifier-noir crate (two directories up from CARGO_MANIFEST_DIR).
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

    // Run `nargo test poseidon2` in that crate.
    let status = Command::new("nargo")
        .args(["test", "poseidon2"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo - is it on PATH?");

    assert!(
        status.success(),
        "nargo test poseidon2 failed (exit code {:?}). \
         The Noir stdlib permutation disagreed with the Rust poseidon2 crate's output \
         on input {:?}. Re-run step 3 in Phase 1A Task 4 to regenerate the expected values.",
        status.code(),
        kat_input(),
    );
}
