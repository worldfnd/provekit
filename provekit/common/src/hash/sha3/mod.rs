mod pow;
mod sponge;
mod whir;

pub use self::{
    whir::Sha3MerkleConfig,
    pow::Sha3PoW,
    sponge::{compress, Sha3Permutation, Sha3Sponge},
};

use {crate::FieldElement, super::traits::ProtocolHash};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sha3;

impl ProtocolHash for Sha3 {
    type Permutation = Sha3Permutation;
    type Sponge = Sha3Sponge;
    type MerkleConfig = Sha3MerkleConfig;
    type PoW = Sha3PoW;

    #[inline]
    fn compress(left: FieldElement, right: FieldElement) -> FieldElement {
        compress(left, right)
    }

    fn name() -> &'static str {
        "sha3"
    }
}
