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

/// The Goldilocks proof field: `Basefield<Field64_3>`.
///
/// Commits the witness in the base field `Field64` and uses the degree-3
/// extension `Field64_3` only for challenges and sumcheck.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoldilocksField;

impl ProofField for GoldilocksField {
    type Embedding = Basefield<Field64_3>;

    const FIELD_ID: u8 = 1;
}

/// Ext-leaf Goldilocks field (`Identity<Field64_3>`, base == ext).
///
/// Used for fixtures that place extension challenge values in the witness,
/// which a base-field witness cannot hold.
// TODO: remove once challenge-bearing fixtures can run under `GoldilocksField`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoldilocksEfField;

impl ProofField for GoldilocksEfField {
    type Embedding = Identity<Field64_3>;

    // Distinct from `GoldilocksField`: the ext-leaf base layout (`Field64_3`)
    // differs from its base-commit layout (`Field64`), so their serialized bytes
    // differ.
    const FIELD_ID: u8 = 2;
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
