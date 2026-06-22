//! The bn254 proof field — `Identity<Fr>` (base == ext) — and the WHIR config
//! aliases specialized to it. This is the concrete instantiation of the
//! field-generic `ProofField`/`FieldHash` traits defined in `provekit-common`.

use {
    crate::{
        bytes::{bytes_to_field, field_to_bytes_le},
        FieldElement, TranscriptSponge,
    },
    provekit_common::{Base, Ext, FieldHash, HashConfig, ProofField},
    whir::{
        algebra::embedding::Identity,
        protocols::{whir::Config as GenericWhirConfig, whir_zk::Config as GenericWhirZkConfig},
    },
};

/// The WHIR config over the bn254 embedding.
pub type WhirConfig = GenericWhirConfig<Identity<FieldElement>>;
/// The zero-knowledge WHIR config over the bn254 extension field.
pub type WhirZkConfig = GenericWhirZkConfig<FieldElement>;

/// bn254 proof field: the `Identity<Fr>` embedding (base == ext).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bn254Field;

impl ProofField for Bn254Field {
    type Embedding = Identity<FieldElement>;
}

impl FieldHash for Bn254Field {
    fn default_hash() -> HashConfig {
        HashConfig::Skyscraper
    }

    fn hash_public_inputs(config: HashConfig, inputs: &[Base<Self>]) -> Ext<Self> {
        crate::field_hash::hash_field_elements(config, inputs)
    }

    fn ext_to_bytes_le(x: &Ext<Self>) -> Vec<u8> {
        field_to_bytes_le(*x).to_vec()
    }

    fn ext_from_bytes(bytes: &[u8]) -> Ext<Self> {
        bytes_to_field(bytes)
    }

    fn from_digest(digest: &[u8]) -> Ext<Self> {
        bytes_to_field(digest)
    }

    type Sponge = TranscriptSponge;

    fn transcript_sponge(config: HashConfig) -> Self::Sponge {
        TranscriptSponge::from_config(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bn254_field_hash_roundtrip() {
        let x: Ext<Bn254Field> = FieldElement::from(123_456_789u64);
        let bytes = Bn254Field::ext_to_bytes_le(&x);
        assert_eq!(bytes.len(), 32);
        assert_eq!(Bn254Field::ext_from_bytes(&bytes), x);
        assert_eq!(Bn254Field::from_digest(&bytes), x);
        assert_eq!(Bn254Field::default_hash(), HashConfig::Skyscraper);
    }

    // Byte-exact public-input hashing is pinned by the KATs in
    // `crate::field_hash::tests` (the bn254 bit-identical regression gate).
}
