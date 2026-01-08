mod pow;
mod sponge;
mod whir;

pub use self::{
    whir::Sha2MerkleConfig,
    pow::Sha2PoW,
    sponge::{compress, Sha2Permutation, Sha2Sponge},
};

use {crate::FieldElement, super::traits::ProtocolHash};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sha2;

impl ProtocolHash for Sha2 {
    type Permutation = Sha2Permutation;
    type Sponge = Sha2Sponge;
    type MerkleConfig = Sha2MerkleConfig;
    type PoW = Sha2PoW;

    #[inline]
    fn compress(left: FieldElement, right: FieldElement) -> FieldElement {
        compress(left, right)
    }

    fn name() -> &'static str {
        "sha2"
    }
}
