use {
    crate::{
        hash::{
            pow::HashPoW,
            sponge::{HashPermutation, HashSponge},
            traits::{HashCore, ProtocolHash},
            utils::{byte_hash_check_pow, byte_hash_compress, byte_hash_permute, byte_hash_solve_pow, ByteHasher},
        },
        FieldElement,
    },
    sha3::{Digest, Sha3_256},
};

#[derive(Clone)]
pub struct Sha3Hasher;

impl ByteHasher for Sha3Hasher {
    fn hash(data: &[u8]) -> [u8; 32] {
        Sha3_256::digest(data).into()
    }
}

impl HashCore for Sha3Hasher {
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

pub type Sha3Permutation = HashPermutation<Sha3Hasher>;
pub type Sha3Sponge = HashSponge<Sha3Hasher>;
pub type Sha3PoW = HashPoW<Sha3Hasher>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sha3;

impl ProtocolHash for Sha3 {
    type Permutation = Sha3Permutation;
    type Sponge = Sha3Sponge;
    type MerkleConfig = Sha3MerkleConfig;
    type PoW = Sha3PoW;

    #[inline]
    fn compress(left: FieldElement, right: FieldElement) -> FieldElement {
        Sha3Hasher::compress(left, right)
    }

    fn name() -> &'static str {
        "sha3"
    }
}

crate::impl_hash_whir!(Sha3, Sha3Hasher);
