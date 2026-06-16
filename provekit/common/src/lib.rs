pub mod field;
pub mod file;
pub use file::binary_format;
pub mod hash_config;
mod interner;
mod mavros;
mod noir_proof_scheme;
pub mod ntt;
pub mod optimize;
pub mod poseidon2;
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
use whir::algebra::embedding::{Embedding, Identity};

/// The proof-system field embedding.
///
/// `field = which embedding you instantiate`. PR A instantiates the spine only
/// at `Identity<bn254::Fr>`; a follow-up adds a second embedding. This type
/// alias is the **single place** the concrete field is chosen — everything
/// downstream resolves [`FieldElement`] through it, so adding a field is a
/// localized change here plus a new [`ProofField`] impl.
pub type ProvekitEmbedding = Identity<ark_bn254::Fr>;

/// The base field the spine stores and operates over.
///
/// Equals `<ProvekitEmbedding as Embedding>::Source` — `bn254::Fr` at
/// `Identity`. At `Identity` the base and extension fields coincide, so the
/// spine needs no base/ext distinction.
pub type FieldElement = <ProvekitEmbedding as Embedding>::Source;

pub use {
    acir::FieldElement as NoirElement,
    field::{DynFieldSponge, ProofField},
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
pub fn register_ntt() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(<FieldElement as ProofField>::register_engines);
}
