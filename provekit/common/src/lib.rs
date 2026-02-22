pub mod file;
mod interner;
mod noir_proof_scheme;
pub mod prefix_covector;
mod prover;
mod r1cs;
pub mod skyscraper;
pub mod sparse_matrix;
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
    noir_proof_scheme::{NoirProof, NoirProofScheme},
    prefix_covector::PrefixCovector,
    prover::Prover,
    r1cs::R1CS,
    verifier::Verifier,
    whir_r1cs::{
        WhirConfig, WhirDomainSeparator, WhirProof, WhirProverState, WhirR1CSProof, WhirR1CSScheme,
        WhirZkConfig,
    },
    witness::PublicInputs,
};

/// SHA-256 based transcript sponge for Fiat-Shamir.
pub type TranscriptSponge = spongefish::instantiations::SHA256;

/// Register provekit's custom implementations in whir's global registries.
///
/// Must be called once before any prove/verify operations.
/// Idempotent — safe to call multiple times.
pub fn register_ntt() {
    use std::sync::{Arc, Once};
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<FieldElement>> =
            Arc::new(whir::algebra::ntt::ArkNtt::<FieldElement>::default());
        whir::algebra::ntt::NTT.insert(ntt);

        let skyscraper: Arc<dyn whir::hash::HashEngine> =
            Arc::new(skyscraper::SkyscraperHashEngine);
        whir::hash::ENGINES.register(skyscraper);
    });
}
