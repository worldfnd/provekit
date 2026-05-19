//! Cross-implementation byte-grain sponge squeeze KAT.
//!
//! 1. Run the canonical byte-grain replay (`squeeze_bytes_kat_expected`) and
//!    sanity-check determinism.
//! 2. Shell out to `nargo test squeeze_bytes` in the sibling Noir crate. That
//!    test runs `Transcript::squeeze_bytes_n::<10>()` over the same canonical
//!    initial state and asserts byte-equality with the frozen
//!    `EXPECTED_SQUEEZE_BYTES_KAT` global.
//! 3. Passing means the Noir byte-grain wrapper agrees with the spongefish-
//!    faithful byte sponge on the canonical KAT.

use {
    provekit_verifier_noir_test::squeeze_bytes_kat_expected,
    std::{path::PathBuf, process::Command},
};

#[test]
fn cross_impl_squeeze_bytes_kat_agrees() {
    let a = squeeze_bytes_kat_expected();
    let b = squeeze_bytes_kat_expected();
    assert_eq!(a, b, "squeeze_bytes_kat_expected non-deterministic");

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
        .args(["test", "squeeze_bytes"])
        .current_dir(&nargo_crate)
        .status()
        .expect("failed to run nargo - is it on PATH?");

    assert!(
        status.success(),
        "nargo test squeeze_bytes failed (exit {:?}). The Noir byte-grain Transcript disagreed \
         with the Rust byte-grain replay on the canonical KAT. Re-run Phase 3B-iii step 5 to \
         regenerate the expected bytes.",
        status.code(),
    );
}
