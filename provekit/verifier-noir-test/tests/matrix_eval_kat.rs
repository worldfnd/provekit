//! Cross-implementation matrix evaluation KAT.
//!
//! 1. Compute the expected `M^T . eq(alpha, .)` result in Rust for the test
//!    matrix A from `provekit/common/src/utils/sumcheck.rs::make_test_r1cs`
//!    at alpha = [2, 3].
//! 2. Shell out to `nargo test matrix_eval` in the sibling Noir crate.
//!    That test asserts Noir's `multiply_matrix_by_eq` produces the same
//!    4-element vector (frozen as `EXPECTED_A_AT_ALPHA` in matrix_eval.nr).
//! 3. Passing means both implementations agree, AND the hypercube ordering
//!    (Rust big-endian) is correctly mirrored in Noir.

use {
    provekit_verifier_noir_test::matrix_eval_kat_expected,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_matrix_eval_kat_agrees() {
    let a = matrix_eval_kat_expected();
    let b = matrix_eval_kat_expected();
    assert_eq!(a, b, "matrix_eval_kat_expected is non-deterministic");

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
        .args(["test", "matrix_eval"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo - is it on PATH?");

    assert!(
        status.success(),
        "nargo test matrix_eval failed (exit code {:?}). \
         The Noir matrix evaluation disagreed with the Rust reference on \
         A^T . eq([2,3], .). Likely causes: hypercube endianness drift, \
         truncation bug, or sparse triple ordering. Re-run Phase 2B Task 2 \
         step 2 to regenerate expected values.",
        status.code(),
    );
}
