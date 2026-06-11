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
