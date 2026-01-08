mod pow;
mod sponge;
mod whir;

pub use self::{
    pow::SkyscraperPoW,
    sponge::{SkyscraperPermutation, SkyscraperSponge},
    whir::{compress, SkyscraperMerkleConfig},
};

use {crate::FieldElement, super::traits::ProtocolHash};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Skyscraper;

impl ProtocolHash for Skyscraper {
    type Permutation = SkyscraperPermutation;
    type Sponge = SkyscraperSponge;
    type MerkleConfig = SkyscraperMerkleConfig;
    type PoW = SkyscraperPoW;

    #[inline]
    fn compress(left: FieldElement, right: FieldElement) -> FieldElement {
        compress(left, right)
    }

    fn name() -> &'static str {
        "skyscraper"
    }
}
