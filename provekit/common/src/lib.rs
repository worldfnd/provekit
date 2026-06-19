pub mod field;
pub mod file;
pub use file::binary_format;
pub mod hash_config;
mod interner;
pub mod optimize;
pub mod prefix_covector;
mod r1cs;
pub mod sparse_matrix;
mod transcript_sponge;
pub mod u256_arith;
pub mod utils;
mod whir_r1cs;
pub mod witness;

use {
    crate::{
        interner::{InternedFieldElement, Interner},
        sparse_matrix::{HydratedSparseMatrix, SparseMatrix},
    },
    whir::algebra::embedding::{Embedding, Identity},
};

// TODO: This is the single bn254 instantiation point. Field selection replaces
// this alias with a `<P: ProofField>` parameter — base = Embedding::Source,
// ext = Embedding::Target — threaded through the interner, r1cs, sparse-matrix
// (HydratedSparseMatrix) and sumcheck, and parameterizes WhirR1CSScheme<P> with
// its WhirConfig/WhirZkConfig aliases. It retires the runtime FieldHashProvider
// registry (field/mod.rs) for compile-time P::method dispatch, genericizes the
// monomorphic serde helpers (utils::serde_ark_vec/serde_ark_option) under
// #[serde(bound = "")], and relocates the 256-bit/PrimeField helpers
// (witness/digits.rs, utils::HALF/uint_to_field, hash_config digest reduction)
// into the field crate. bn254 stays Identity<Fr> (base == ext), byte-identical.
/// The proof-system field embedding (currently `Identity<bn254::Fr>`).
///
/// This is the bn254 instantiation point: because `Identity` has
/// `Source == Target`, the spine names a single [`FieldElement`] for both
/// committed data (`Embedding::Source`) and challenges (`Embedding::Target`).
pub type ProvekitEmbedding = Identity<ark_bn254::Fr>;

/// The base field the spine operates over (`bn254::Fr` at `Identity`).
pub type FieldElement = <ProvekitEmbedding as Embedding>::Source;

pub use {
    field::{
        ensure_field_backend_registered, register_field_hash_provider, DynFieldSponge,
        FieldHashProvider,
    },
    hash_config::{FieldNativeHashConfig, HashConfig},
    prefix_covector::{OffsetCovector, PrefixCovector, SparseCovector},
    r1cs::R1CS,
    transcript_sponge::TranscriptSponge,
    whir_r1cs::{R1csHash, WhirConfig, WhirR1CSProof, WhirR1CSScheme, WhirZkConfig},
    witness::PublicInputs,
};
