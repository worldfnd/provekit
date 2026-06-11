// `bn254` takes precedence when both field features are enabled (CI builds
// with `--all-features`, which unavoidably turns both on). A goldilocks
// build must therefore disable the default:
//   cargo build -p provekit-common -p provekit-prover -p provekit-verifier \
//       --no-default-features --features goldilocks
#[cfg(not(any(feature = "bn254", feature = "goldilocks")))]
compile_error!("enable a field feature: `bn254` (default) or `goldilocks`");

pub mod file;
pub use file::binary_format;
pub mod hash_config;
mod interner;
#[cfg(feature = "bn254")]
mod mavros;
#[cfg(feature = "bn254")]
mod noir_proof_scheme;
#[cfg(feature = "bn254")]
pub mod ntt;
#[cfg(feature = "bn254")]
pub mod optimize;
#[cfg(feature = "bn254")]
pub mod poseidon2;
pub mod prefix_covector;
#[cfg(feature = "bn254")]
mod prover;
mod r1cs;
#[cfg(feature = "bn254")]
pub mod skyscraper;
pub mod sparse_matrix;
mod transcript_sponge;
pub mod u256_arith;
pub mod utils;
#[cfg(feature = "bn254")]
mod verifier;
mod whir_r1cs;
pub mod witness;

use crate::{
    interner::{InternedFieldElement, Interner},
    sparse_matrix::{HydratedSparseMatrix, SparseMatrix},
};
/// The proof system's field. BN254 scalar field by default; the Goldilocks
/// cubic extension (`Field64_3`, ~192 bits — `Field`/`FftField` but not
/// `PrimeField`) under the `goldilocks` feature.
#[cfg(feature = "bn254")]
pub use ark_bn254::Fr as FieldElement;
#[cfg(all(feature = "goldilocks", not(feature = "bn254")))]
pub use whir::algebra::fields::Field64_3 as FieldElement;

/// Which field [`FieldElement`] resolved to in this build: `true` for the
/// BN254 scalar field, `false` for the Goldilocks cubic extension. Because
/// `bn254` wins precedence when both features are on, this tracks the actual
/// type — not merely whether `goldilocks` was requested.
///
/// Downstream crates that carry their own `bn254`/`goldilocks` features assert
/// their intent against this via [`assert_field_matches_common`], so Cargo
/// feature unification (a sibling forcing `provekit-common/bn254` while the
/// crate was built for `goldilocks`) becomes a build error rather than silently
/// compiling field-gated code over the wrong `FieldElement`.
pub const FIELD_IS_BN254: bool = cfg!(feature = "bn254");

/// Compile-time guard that the invoking crate's field feature matches
/// [`FIELD_IS_BN254`] (i.e. `provekit-common`'s resolved [`FieldElement`]).
///
/// Invoke once at crate root in any crate that has its own `bn254`/`goldilocks`
/// features and uses [`FieldElement`]. `cfg!(feature = "bn254")` is evaluated
/// in the caller, so a divergence introduced by feature unification fails the
/// build with a clear message instead of producing a wrong-field binary.
#[macro_export]
macro_rules! assert_field_matches_common {
    () => {
        const _: () = ::core::assert!(
            ::core::cfg!(feature = "bn254") == $crate::FIELD_IS_BN254,
            "this crate's field feature disagrees with provekit-common's resolved FieldElement: a \
             sibling crate likely enabled provekit-common/bn254 via Cargo feature unification \
             while this crate was built for goldilocks. Build every provekit crate in the \
             dependency graph over the same field.",
        );
    };
}
#[cfg(feature = "bn254")]
pub use {
    acir::FieldElement as NoirElement,
    mavros::{MavrosProver, MavrosSchemeData},
    noir_proof_scheme::{NoirProof, NoirProofScheme, NoirSchemeData},
    prover::{NoirProver, Prover},
    verifier::Verifier,
};
pub use {
    hash_config::HashConfig,
    prefix_covector::{OffsetCovector, PrefixCovector, SparseCovector},
    r1cs::R1CS,
    transcript_sponge::TranscriptSponge,
    whir_r1cs::{
        R1csHash, WhirConfig, WhirR1CSProof, WhirR1CSScheme, WhirR1CSSchemeBuilder, WhirZkConfig,
    },
    witness::PublicInputs,
};

/// Register provekit's custom implementations in whir's global registries.
///
/// Must be called once before any prove/verify operations.
/// Idempotent — safe to call multiple times.
pub fn register_ntt() {
    use std::sync::{Arc, Once};
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // Register NTT for polynomial operations
        #[cfg(not(feature = "provekit_ntt"))]
        let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<FieldElement>> =
            Arc::new(whir::algebra::ntt::NttEngine::<FieldElement>::new_from_fftfield());

        #[cfg(feature = "provekit_ntt")]
        let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<FieldElement>> =
            Arc::new(crate::ntt::RSFr);

        whir::algebra::ntt::NTT.insert(ntt);

        // Register ProveKit-specific engines; WHIR's built-in engines
        // (SHA2, Keccak, Blake3, etc.) are pre-registered via whir::hash::ENGINES.
        // Skyscraper and Poseidon2 are BN254-only constructions.
        #[cfg(feature = "bn254")]
        {
            whir::hash::ENGINES.register(Arc::new(skyscraper::SkyscraperHashEngine));
            whir::hash::ENGINES.register(Arc::new(poseidon2::Poseidon2HashEngine));
        }
    });
}
