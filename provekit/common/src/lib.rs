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

/// Register provekit's custom implementations in whir's global registries.
///
/// Must be called once before any prove/verify operations.
/// Idempotent — safe to call multiple times.
pub fn register_whir_backends() {
    use std::sync::{Arc, Once};
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        #[cfg(not(feature = "provekit_ntt"))]
        let irs_committer: Arc<
            dyn whir::protocols::irs_commit::IrsCommitter<FieldElement>,
        > = Arc::new(whir::protocols::irs_commit::CpuIrsCommitter::new(Arc::new(
            crate::ntt::RSFr,
        )));

        #[cfg(feature = "provekit_ntt")]
        let irs_committer: Arc<
            dyn whir::protocols::irs_commit::IrsCommitter<FieldElement>,
        > = match crate::ntt::MetalBn254Ntt::new() {
            Ok(ntt) => Arc::new(ntt),
            Err(err) => {
                tracing::info!(
                    error = %err,
                    "Metal BN254 IRS backend unavailable, using ProveKit CPU fallback"
                );
                Arc::new(whir::protocols::irs_commit::CpuIrsCommitter::new(Arc::new(
                    crate::ntt::RSFr,
                )))
            }
        };

        whir::protocols::irs_commit::IRS_COMMITTERS.insert(irs_committer);

        // Register Skyscraper (ProveKit-specific); WHIR's built-in engines
        // (SHA2, Keccak, Blake3, etc.) are pre-registered via whir::hash::ENGINES.
        whir::hash::ENGINES.register(Arc::new(skyscraper::SkyscraperHashEngine));
    });
}
