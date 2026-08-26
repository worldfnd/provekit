//! Field abstraction for the generic proof-system spine.

use {
    ark_ff::FftField,
    std::fmt::Debug,
    whir::{algebra::embedding::Embedding, transcript::Codec},
};

/// Algebra carrier for a proof field: `Embedding::Source` is the base
/// (committed) field, `Embedding::Target` the extension (challenge) field.
///
/// bn254 uses `Identity<Fr>` (base == ext); a field with a genuine
/// extension uses an embedding whose source and target differ (e.g.
/// `Basefield<Field64_3>`).
pub trait ProofField: Copy + Debug + Eq + Send + Sync {
    /// `Default` lets the spine construct the embedding instance for mixed
    /// base×ext products (`Identity`/`Basefield` both derive it). The extension
    /// (`Target`) must be FFT-friendly and transcript-codec-able — WHIR's
    /// requirement for any challenge/commitment field.
    type Embedding: Embedding<Target: FftField + Codec> + Default;

    /// Per-field tag folded into the `.np` proof magic so one field's proof is
    /// rejected by another field's verifier. Must be unique per field; bn254
    /// reserves `0` to keep its legacy magic byte-identical.
    const FIELD_ID: u8;
}

/// Base (committed) field of a [`ProofField`].
pub type Base<P> = <<P as ProofField>::Embedding as Embedding>::Source;

/// Extension (challenge) field of a [`ProofField`].
pub type Ext<P> = <<P as ProofField>::Embedding as Embedding>::Target;

/// Hash and byte-bridge glue, kept out of [`ProofField`]'s algebra surface and
/// composed as a supertrait so [`Ext<Self>`] is nameable.
pub trait FieldHash: ProofField {
    /// Register this field's engines in WHIR's global registries.
    ///
    /// Implementations must be idempotent.
    fn register();

    /// Instance-binding hash of base-field public inputs to an extension
    /// transcript element.
    fn hash_public_inputs(config: crate::HashConfig, inputs: &[Base<Self>]) -> Ext<Self>;

    /// Little-endian bytes of an extension element (32B for `Fr`, 24B for
    /// `Field64_3`).
    fn ext_to_bytes_le(x: &Ext<Self>) -> Vec<u8>;

    /// Fiat-Shamir transcript sponge for this field, selected at runtime by
    /// [`crate::HashConfig`]. Byte-oriented (`U = u8`) so the spine names it
    /// generically without depending on any concrete field's hash.
    type Sponge: spongefish::DuplexSpongeInterface<U = u8> + Send;

    /// Construct the transcript sponge matching `config`.
    fn transcript_sponge(config: crate::HashConfig) -> Self::Sponge;

    // TODO: add a base-field (`Source`) byte bridge when one is needed.
}
