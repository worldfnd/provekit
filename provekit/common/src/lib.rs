pub mod bigint_mod;
mod compress;
pub mod ec_arith;
pub mod file;
pub use file::binary_format;
pub mod field;
pub mod hash_config;
mod interner;
mod logging;
pub mod ntt;
pub mod optimize;
pub mod poseidon2;
pub mod prefix_covector;
mod r1cs;
pub mod skyscraper;
pub mod sparse_matrix;
mod transcript_sponge;
pub mod u256_arith;
pub mod utils;
mod whir_r1cs;
pub mod witness;

use crate::{
    interner::{InternedFieldElement, Interner},
    sparse_matrix::{HydratedSparseMatrix, SparseMatrix},
};
pub use {
    // TODO(P0.4): bn254-only alias and the migration lynchpin. Deleting it (once
    // provekit-backend-bn254 owns `Fr`) is the final P0.4 step; it forces removal
    // of every `= FieldElement` / `= Bn254Field` default type param across the
    // spine. The compiler flags each site, so those defaults need no individual
    // markers.
    ark_bn254::Fr as FieldElement,
    compress::{CompressedLayers, CompressedR1CS},
    field::{Base, Ext, FieldHash, ProofField},
    hash_config::HashConfig,
    logging::log_commit_input,
    prefix_covector::{OffsetCovector, PrefixCovector, SparseCovector},
    r1cs::R1CS,
    transcript_sponge::TranscriptSponge,
    whir_r1cs::{ProvekitProof, R1csHash, WhirR1CSProof, WhirR1CSScheme},
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
        whir::hash::ENGINES.register(Arc::new(skyscraper::SkyscraperHashEngine));
        whir::hash::ENGINES.register(Arc::new(poseidon2::Poseidon2HashEngine));
    });
}
