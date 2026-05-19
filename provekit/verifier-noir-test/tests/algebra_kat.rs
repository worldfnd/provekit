//! Cross-impl algebra helpers (tensor_product, mle_evaluate) KAT.

use {
    provekit_verifier_noir_test::{mle_evaluate_kat_expected, tensor_product_kat_expected},
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_algebra_kat_agrees() {
    // Rust-side determinism.
    let t_a = tensor_product_kat_expected();
    let t_b = tensor_product_kat_expected();
    assert_eq!(t_a, t_b, "tensor_product_kat_expected non-deterministic");
    let m_a = mle_evaluate_kat_expected();
    let m_b = mle_evaluate_kat_expected();
    assert_eq!(m_a, m_b, "mle_evaluate_kat_expected non-deterministic");

    // Spot-check the Rust expected values against hand computation:
    //   tensor_product([2,3], [5,7]) = [10, 14, 15, 21]
    //   mle_evaluate([1,2,3,4], [2,3]) = 8
    assert_eq!(t_a[0], ark_bn254::Fr::from(10u64));
    assert_eq!(t_a[1], ark_bn254::Fr::from(14u64));
    assert_eq!(t_a[2], ark_bn254::Fr::from(15u64));
    assert_eq!(t_a[3], ark_bn254::Fr::from(21u64));
    assert_eq!(m_a, ark_bn254::Fr::from(8u64));

    // Run the Noir-side tests via nargo.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let nargo_crate = manifest_dir
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .join("verifier-noir");
    assert!(nargo_crate.join("Nargo.toml").exists());

    // Both Noir tests are pure-formula; together with the matrix_eval test
    // they all live under the matrix_eval filter.
    let status = Command::new("nargo")
        .args(["test", "matrix_eval"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo");
    assert!(
        status.success(),
        "nargo test matrix_eval failed (exit {:?})",
        status.code(),
    );

    // Also explicitly test the two new helpers by name.
    let status = Command::new("nargo")
        .args(["test", "tensor_product"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo");
    assert!(status.success(), "nargo test tensor_product failed");

    let status = Command::new("nargo")
        .args(["test", "mle_evaluate"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo");
    assert!(status.success(), "nargo test mle_evaluate failed");
}
