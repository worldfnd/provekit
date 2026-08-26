//! The Goldilocks proof fields (base-leaf and ext-leaf) and their shared
//! `FieldHash` glue.

use {
    crate::{bytes::field_to_bytes_le, field_hash::hash_field_elements, TranscriptSponge},
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

/// Goldilocks proof field with the identity embedding (`Identity<Field64_3>`,
/// base == ext): challenges are both drawn from and committed in the full
/// `Field64_3` extension.
///
/// Serves challenge-bearing circuits, where an extension challenge cannot be
/// stored in a base-field (`Field64`) witness slot; committing in the extension
/// keeps 128-bit soundness.
// TODO: `GoldilocksField` (base-committed) can subsume this once it binds
// challenges directly — needs (1) a base transcript codec so base challenges can
// be drawn from Fiat-Shamir (the `FieldHash` `Source` byte bridge), and (2)
// k-fold repetition, since a single `Field64` challenge is only ~64-bit sound.
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
            fn register() {
                crate::register();
            }

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
    };
}

impl_goldilocks_field_hash!(GoldilocksField);
impl_goldilocks_field_hash!(GoldilocksEfField);

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
