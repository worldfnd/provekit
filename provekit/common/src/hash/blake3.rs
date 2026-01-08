use crate::{
    hash::{
        pow::HashPoW,
        sponge::{HashPermutation, HashSponge},
        traits::{HashCore, ProtocolHash},
        utils::{
            byte_hash_check_pow, byte_hash_compress, byte_hash_permute, byte_hash_solve_pow,
            ByteHasher,
        },
    },
    FieldElement,
};

#[derive(Clone)]
pub struct Blake3Hasher;

impl ByteHasher for Blake3Hasher {
    fn hash(data: &[u8]) -> [u8; 32] {
        blake3::hash(data).into()
    }
}

impl HashCore for Blake3Hasher {
    fn compress(left: FieldElement, right: FieldElement) -> FieldElement {
        byte_hash_compress::<Self>(left, right)
    }

    fn permute(left: FieldElement, right: FieldElement) -> (FieldElement, FieldElement) {
        byte_hash_permute::<Self>(left, right)
    }

    fn solve_pow(challenge: [u8; 32], bits: f64) -> Option<u64> {
        byte_hash_solve_pow::<Self>(challenge, bits)
    }

    fn check_pow(challenge: [u8; 32], bits: f64, nonce: u64) -> bool {
        byte_hash_check_pow::<Self>(challenge, bits, nonce)
    }
}

pub type Blake3Permutation = HashPermutation<Blake3Hasher>;
pub type Blake3Sponge = HashSponge<Blake3Hasher>;
pub type Blake3PoW = HashPoW<Blake3Hasher>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Blake3;

impl ProtocolHash for Blake3 {
    type Permutation = Blake3Permutation;
    type Sponge = Blake3Sponge;
    type MerkleConfig = Blake3MerkleConfig;
    type PoW = Blake3PoW;

    #[inline]
    fn compress(left: FieldElement, right: FieldElement) -> FieldElement {
        Blake3Hasher::compress(left, right)
    }

    fn name() -> &'static str {
        "blake3"
    }
}

crate::impl_hash_whir!(Blake3, Blake3Hasher);
