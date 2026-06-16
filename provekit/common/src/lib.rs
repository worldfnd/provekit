pub mod field;
pub mod file;
pub use file::binary_format;
pub mod hash_config;
mod interner;
mod mavros;
mod noir_proof_scheme;
pub mod optimize;
pub mod prefix_covector;
mod prover;
mod r1cs;
pub mod sparse_matrix;
mod transcript_sponge;
pub mod u256_arith;
pub mod utils;
mod verifier;
mod whir_r1cs;
pub mod witness;

use {
    crate::{
        interner::{InternedFieldElement, Interner},
        sparse_matrix::{HydratedSparseMatrix, SparseMatrix},
    },
    whir::algebra::embedding::{Embedding, Identity},
};

/// The proof-system field embedding (currently `Identity<bn254::Fr>`).
///
/// This is the single place the field is chosen: change it and add a matching
/// [`FieldHashProvider`] impl to switch fields.
pub type ProvekitEmbedding = Identity<ark_bn254::Fr>;

/// The base field the spine operates over (`bn254::Fr` at `Identity`).
pub type FieldElement = <ProvekitEmbedding as Embedding>::Source;

pub use {
    acir::FieldElement as NoirElement,
    field::{register_field_hash_provider, DynFieldSponge, FieldHashProvider},
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
