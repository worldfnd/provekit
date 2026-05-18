//! Cross-implementation Spartan sumcheck KAT.
//!
//! 1. Construct a valid 2-round Spartan sumcheck transcript in Rust:
//!    `sum_g = 12`, `blinding_eval = 7`, `h_i = [saved/2, 0, 0, 0]` each round.
//!    The Rust replay derives `f_at_alpha`.
//! 2. Shell out to `nargo test sumcheck_verifier_matches_frozen_kat`.
//!    That test runs the same `(sum_g, h_polys, blinding_eval)` through
//!    Noir's `run_sumcheck_verifier` and asserts `f_at_alpha` matches.
//! 3. Passing means both implementations agree on this synthetic transcript.

use {
    provekit_verifier_noir_test::sumcheck_kat_construct,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_sumcheck_kat_agrees() {
    let (h_a, f_a) = sumcheck_kat_construct();
    let (h_b, f_b) = sumcheck_kat_construct();
    assert_eq!(h_a, h_b, "sumcheck_kat_construct non-deterministic on h_polys");
    assert_eq!(f_a, f_b, "sumcheck_kat_construct non-deterministic on f_at_alpha");

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
        .args(["test", "sumcheck_verifier_matches_frozen_kat"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo - is it on PATH?");

    assert!(
        status.success(),
        "nargo test sumcheck_verifier_matches_frozen_kat failed (exit code {:?}). \
         The Noir sumcheck verifier disagreed with the Rust replay on the canonical KAT. \
         Re-run Phase 2A Task 4 step 2 to regenerate the expected values.",
        status.code(),
    );
}
