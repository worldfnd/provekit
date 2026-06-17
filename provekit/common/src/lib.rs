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

/// The proof-system field embedding (currently `Identity<bn254::Fr>`).
///
/// This is the bn254 instantiation point. Because `Identity` has
/// `Source == Target`, the spine names a single [`FieldElement`] for both
/// committed data and challenges. Switching to an embedding with a distinct
/// extension (e.g. Goldilocks `Basefield<Field64_3>`) is **not** just changing
/// this alias: committed data must stay in `Embedding::Source` while challenges
/// move to `Embedding::Target`, which requires threading `<M: Embedding>`
/// through the algebra (interner / r1cs / sparse-matrix / sumcheck). Tracked
/// for the field-selection PR.
pub type ProvekitEmbedding = Identity<ark_bn254::Fr>;

/// The base field the spine operates over (`bn254::Fr` at `Identity`).
pub type FieldElement = <ProvekitEmbedding as Embedding>::Source;

pub use {
    field::{register_field_hash_provider, DynFieldSponge, FieldHashProvider},
    hash_config::HashConfig,
    prefix_covector::{OffsetCovector, PrefixCovector, SparseCovector},
    r1cs::R1CS,
    transcript_sponge::TranscriptSponge,
    whir_r1cs::{R1csHash, WhirConfig, WhirR1CSProof, WhirR1CSScheme, WhirZkConfig},
    witness::PublicInputs,
};
