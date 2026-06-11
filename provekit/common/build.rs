//! Build script for `provekit-common`.
//!
//! Surfaces the one field-feature footgun the `compile_error!` in `src/lib.rs`
//! cannot catch. `bn254` wins cfg precedence over `goldilocks` (so the crate
//! builds as BN254 whenever both are on — the intended resolution under
//! `--all-features`, which CI uses). But several BN254-only features pull in
//! `bn254` transitively (`provekit_ntt`, and the prover's
//! `witness-generation`), so an explicit `--features goldilocks,<that>` build
//! silently compiles as BN254 instead of Goldilocks. `compile_error!` only
//! fires when *no* field is selected, never here.
//!
//! A `cargo:warning` makes the override visible without failing the build
//! (a hard error would break the legitimate `--all-features` path). Build-
//! script warnings are advisory, so this is safe even under `-D warnings`.
fn main() {
    let bn254 = std::env::var_os("CARGO_FEATURE_BN254").is_some();
    let goldilocks = std::env::var_os("CARGO_FEATURE_GOLDILOCKS").is_some();
    if bn254 && goldilocks {
        println!(
            "cargo:warning=provekit-common: both `bn254` and `goldilocks` features are enabled; \
             FieldElement is BN254 (bn254 takes precedence), so `goldilocks` is inert. For a real \
             Goldilocks build use `--no-default-features --features goldilocks` and drop any \
             feature that pulls in bn254 (provekit_ntt, the prover's witness-generation). This \
             warning is expected under --all-features."
        );
    }
}
