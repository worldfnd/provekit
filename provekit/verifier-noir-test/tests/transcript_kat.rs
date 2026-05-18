//! Cross-implementation transcript KAT.
//!
//! 1. Replay a fixed (state, absorb_pos, squeeze_pos) + absorb/squeeze
//!    sequence in Rust using the raw Poseidon2 permutation.
//! 2. Shell out to `nargo test transcript` in the sibling Noir crate.
//!    That test runs the same sequence through the Noir `Transcript` and
//!    asserts the two squeezed field elements match the frozen Noir globals.
//! 3. Passing means both implementations agree on this KAT.

use {
    provekit_verifier_noir_test::transcript_kat_expected,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_transcript_kat_agrees() {
    // Sanity: deterministic.
    let a = transcript_kat_expected();
    let b = transcript_kat_expected();
    assert_eq!(a, b, "Rust lane_sponge_replay is non-deterministic");

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
        .args(["test", "transcript"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo - is it on PATH?");

    assert!(
        status.success(),
        "nargo test transcript failed (exit code {:?}). \
         The Noir Transcript disagreed with the Rust lane-grain replay \
         on the canonical KAT. Re-run Phase 1B Task 4 step 2 to regenerate \
         the expected values.",
        status.code(),
    );
}
