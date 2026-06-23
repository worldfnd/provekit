//! The Goldilocks degree-3 extension proof field and its `FieldHash` glue.

use {
    crate::{
        bytes::{bytes_to_field, field_to_bytes_le},
        field_hash::{digest_to_field, hash_field_elements},
        TranscriptSponge,
    },
    provekit_common::{Base, Ext, FieldHash, HashConfig, ProofField},
    whir::algebra::{embedding::Identity, fields::Field64_3},
};

/// Goldilocks degree-3 extension proof field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoldilocksField;

impl ProofField for GoldilocksField {
    type Embedding = Identity<Field64_3>;
}

impl FieldHash for GoldilocksField {
    fn default_hash() -> HashConfig {
        HashConfig::Sha256
    }

    fn hash_public_inputs(config: HashConfig, inputs: &[Base<Self>]) -> Ext<Self> {
        hash_field_elements(config, inputs)
    }

    fn ext_to_bytes_le(x: &Ext<Self>) -> Vec<u8> {
        field_to_bytes_le(*x).to_vec()
    }

    fn ext_from_bytes(bytes: &[u8]) -> Ext<Self> {
        bytes_to_field(bytes)
    }

    fn from_digest(digest: &[u8]) -> Ext<Self> {
        digest_to_field(digest)
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
    fn ext_byte_roundtrip() {
        let x: Ext<GoldilocksField> = Field64_3::from(123_456_789u64);
        let bytes = GoldilocksField::ext_to_bytes_le(&x);
        assert_eq!(bytes.len(), 24);
        assert_eq!(GoldilocksField::ext_from_bytes(&bytes), x);
        assert_eq!(GoldilocksField::default_hash(), HashConfig::Sha256);
    }
}
