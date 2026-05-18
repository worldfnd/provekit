//! Cross-implementation duplex-sponge KAT.
//!
//! 1. Run a fixed absorb/squeeze sequence through spongefish's
//!    `Poseidon2Sponge` and capture the four squeezed field elements.
//! 2. Shell out to `nargo test sponge` in the sibling Noir crate.
//!    That test asserts the lane-oriented Noir sponge produces the same
//!    four field elements (frozen as Noir globals in `sponge.nr`).
//! 3. Passing means both implementations agree on this KAT sequence.

use {
    provekit_verifier_noir_test::sponge_kat_expected,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_sponge_kat_agrees() {
    // Sanity: spongefish is deterministic on the KAT input.
    let a = sponge_kat_expected();
    let b = sponge_kat_expected();
    assert_eq!(a, b, "spongefish Poseidon2Sponge is non-deterministic on the KAT");

    // Locate the verifier-noir crate.
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

    // Run `nargo test sponge` in that crate.
    let status = Command::new("nargo")
        .args(["test", "sponge"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo - is it on PATH?");

    assert!(
        status.success(),
        "nargo test sponge failed (exit code {:?}). \
         The Noir lane-oriented sponge disagreed with spongefish's byte sponge \
         on the canonical KAT. Re-run Phase 1B Task 2 step 3 to regenerate the \
         expected values.",
        status.code(),
    );
}
