//! The Goldilocks proof fields (base-leaf and ext-leaf) and their shared
//! `FieldHash` glue.

use {
    crate::{
        bytes::{bytes_to_field, field_to_bytes_le},
        field_hash::{digest_to_field, hash_field_elements},
        TranscriptSponge,
    },
    provekit_common::{Base, Ext, FieldHash, HashConfig, ProofField},
    whir::algebra::{
        embedding::{Basefield, Identity},
        fields::Field64_3,
    },
};

/// Goldilocks degree-3 extension proof field, base-leaf (BF) variant.
///
/// Commits the witness in the base field `Field64` (BF) and uses the degree-3
/// extension `Field64_3` (EF) only for challenges and sumcheck.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoldilocksField;

impl ProofField for GoldilocksField {
    type Embedding = Basefield<Field64_3>;
}

/// Goldilocks degree-3 extension proof field, ext-leaf (EF) variant.
///
/// `Identity` embedding (base == ext == `Field64_3`): the witness is committed
/// in the extension field. This is the same-field baseline for BF-vs-EF
/// profiling — identical sumcheck, only the commitment leaf field differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoldilocksEfField;

impl ProofField for GoldilocksEfField {
    type Embedding = Identity<Field64_3>;
}

/// Both Goldilocks fields share the same hash/byte glue: the challenge field is
/// `Field64_3` either way, and the public-input hash is base-generic.
macro_rules! impl_goldilocks_field_hash {
    ($field:ty) => {
        impl FieldHash for $field {
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
    };
}

impl_goldilocks_field_hash!(GoldilocksField);
impl_goldilocks_field_hash!(GoldilocksEfField);

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
