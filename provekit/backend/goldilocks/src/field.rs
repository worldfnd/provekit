//! The Goldilocks degree-3 extension proof field and its `FieldHash` glue.

use {
    crate::{bytes::field_to_bytes_le, field_hash::hash_field_elements, TranscriptSponge},
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
    fn hash_public_inputs(config: HashConfig, inputs: &[Base<Self>]) -> Ext<Self> {
        hash_field_elements(config, inputs)
    }

    fn ext_to_bytes_le(x: &Ext<Self>) -> Vec<u8> {
        field_to_bytes_le(*x).to_vec()
    }

    type Sponge = TranscriptSponge;

    fn transcript_sponge(config: HashConfig) -> Self::Sponge {
        TranscriptSponge::from_config(config)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::bytes::bytes_to_field};

    #[test]
    fn ext_byte_roundtrip() {
        let x: Ext<GoldilocksField> = Field64_3::from(123_456_789u64);
        let bytes = GoldilocksField::ext_to_bytes_le(&x);
        assert_eq!(bytes.len(), 24);
        assert_eq!(bytes_to_field(&bytes), x);
    }
}
