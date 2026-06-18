//! Field abstraction for the generic proof-system spine.

use {std::fmt::Debug, whir::algebra::embedding::Embedding};

/// Algebra carrier for a proof field: `Embedding::Source` is the base
/// (committed) field, `Embedding::Target` the extension (challenge) field.
///
/// bn254 uses `Identity<Fr>` (base == ext); goldilocks uses
/// `Identity<Field64_3>` pre-v3, `Basefield<Field64_3>` once zkWHIR v3 lands.
pub trait ProofField: Copy + Debug + Eq + Send + Sync {
    type Embedding: Embedding;
}

/// Base (committed) field of a [`ProofField`].
pub type Base<P> = <<P as ProofField>::Embedding as Embedding>::Source;

/// Extension (challenge) field of a [`ProofField`].
pub type Ext<P> = <<P as ProofField>::Embedding as Embedding>::Target;

/// Hash and byte-bridge glue, kept out of [`ProofField`]'s algebra surface and
/// composed as a supertrait so [`Ext<Self>`] is nameable.
pub trait FieldHash: ProofField {
    fn default_hash() -> crate::HashConfig;

    /// Little-endian bytes of an extension element (32B for `Fr`, 24B for
    /// `Field64_3`).
    fn ext_to_bytes_le(x: &Ext<Self>) -> Vec<u8>;

    fn ext_from_bytes(bytes: &[u8]) -> Ext<Self>;

    /// Reduce a hash digest to an extension element.
    fn from_digest(digest: &[u8]) -> Ext<Self>;

    // TODO(base-bridge): add a base (`Source`) bridge when base commitment lands
    // (V-stage).
}
