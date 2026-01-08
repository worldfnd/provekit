mod pow;
mod sponge;
mod whir;

pub use self::{
    whir::Blake3MerkleConfig,
    pow::Blake3PoW,
    sponge::{compress, Blake3Permutation, Blake3Sponge},
};

use {crate::FieldElement, super::traits::ProtocolHash};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Blake3;

impl ProtocolHash for Blake3 {
    type Permutation = Blake3Permutation;
    type Sponge = Blake3Sponge;
    type MerkleConfig = Blake3MerkleConfig;
    type PoW = Blake3PoW;

    #[inline]
    fn compress(left: FieldElement, right: FieldElement) -> FieldElement {
        compress(left, right)
    }

    fn name() -> &'static str {
        "blake3"
    }
}
