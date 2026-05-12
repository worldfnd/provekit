#![deny(unsafe_op_in_unsafe_fn)]

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
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let irs_committer = build_irs_committer();
        whir::protocols::irs_commit::IRS_COMMITTERS.insert(irs_committer);

        // Register Skyscraper (ProveKit-specific); WHIR's built-in engines
        // (SHA2, Keccak, Blake3, etc.) are pre-registered via whir::hash::ENGINES.
        whir::hash::ENGINES
            .register(std::sync::Arc::new(skyscraper::SkyscraperHashEngine));
    });
}

/// Build the IRS committer for BN254.
///
/// With `provekit_ntt`: uses ProveKit's optimized NTT backends (Metal on
/// macOS with CPU fallback, CPU-only on other targets).
/// Without `provekit_ntt`: uses whir's built-in `NttEngine`.
fn build_irs_committer()
-> std::sync::Arc<dyn whir::protocols::irs_commit::IrsCommitter<FieldElement>> {
    use std::sync::Arc;
    use whir::protocols::irs_commit::CpuIrsCommitter;

    #[cfg(feature = "provekit_ntt")]
    {
        #[cfg(target_os = "macos")]
        match crate::ntt::MetalBn254Ntt::new() {
            Ok(ntt) => return Arc::new(ntt),
            Err(err) => {
                tracing::info!(
                    error = %err,
                    "Metal BN254 IRS backend unavailable, using ProveKit CPU fallback"
                );
            }
        }

        #[cfg(target_os = "linux")]
        match crate::ntt::CudaBn254Ntt::new() {
            Ok(ntt) => return Arc::new(ntt),
            Err(err) => {
                tracing::info!(
                    error = %err,
                    "CUDA BN254 IRS backend unavailable, using ProveKit CPU fallback"
                );
            }
        }

        Arc::new(CpuIrsCommitter::new(Arc::new(crate::ntt::RSFr)))
    }

    #[cfg(not(feature = "provekit_ntt"))]
    {
        Arc::new(CpuIrsCommitter::new(Arc::new(
            whir::algebra::ntt::NttEngine::<FieldElement>::new_from_fftfield(),
        )))
    }
}
