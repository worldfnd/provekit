pub mod file;
pub use file::binary_format;
pub mod hash_config;
mod interner;
mod mavros;
mod noir_proof_scheme;
pub mod ntt;
pub mod optimize;
pub mod prefix_covector;
mod prover;
mod r1cs;
pub mod skyscraper;
pub mod sparse_matrix;
mod transcript_sponge;
pub mod u256_arith;
pub mod utils;
mod verifier;
mod whir_r1cs;
pub mod witness;

use crate::{
    interner::{InternedFieldElement, Interner},
    sparse_matrix::{HydratedSparseMatrix, SparseMatrix},
};
pub use {
    acir::FieldElement as NoirElement,
    ark_bn254::Fr as FieldElement,
    hash_config::HashConfig,
    mavros::{MavrosProver, MavrosSchemeData},
    noir_proof_scheme::{NoirProof, NoirProofScheme, NoirSchemeData},
    prefix_covector::{OffsetCovector, PrefixCovector, SparseCovector},
    prover::{NoirProver, Prover},
    r1cs::R1CS,
    transcript_sponge::TranscriptSponge,
    verifier::Verifier,
    whir_r1cs::{R1csHash, WhirConfig, WhirR1CSProof, WhirR1CSScheme, WhirZkConfig},
    witness::PublicInputs,
};

static FIELD_HASHER_FN: std::sync::OnceLock<fn(&[FieldElement]) -> FieldElement> =
    std::sync::OnceLock::new();

/// Returns the registered public-inputs hasher. Panics if
/// [`register_hash_config`] was not called.
pub(crate) fn field_hasher() -> fn(&[FieldElement]) -> FieldElement {
    *FIELD_HASHER_FN
        .get()
        .expect("register_hash_config must be called before hashing public inputs")
}

/// Register the global public-inputs field hasher. Call once at startup
/// alongside [`register_ntt`].
///
/// Idempotent — subsequent calls with a different config are silently ignored;
/// the first caller wins. This matches the `register_ntt` contract.
pub fn register_hash_config(config: HashConfig) {
    FIELD_HASHER_FN.get_or_init(|| witness::field_hasher_for(config));
}

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

        // Register Skyscraper (ProveKit-specific); WHIR's built-in engines
        // (SHA2, Keccak, Blake3, etc.) are pre-registered via whir::hash::ENGINES.
        whir::hash::ENGINES.register(Arc::new(skyscraper::SkyscraperHashEngine));
    });
}
