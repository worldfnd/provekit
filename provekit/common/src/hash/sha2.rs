use {
    crate::{
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
    },
    sha2::{Digest, Sha256},
};

#[derive(Clone)]
pub struct Sha2Hasher;

impl ByteHasher for Sha2Hasher {
    fn hash(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }
}

impl HashCore for Sha2Hasher {
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

pub type Sha2Permutation = HashPermutation<Sha2Hasher>;
pub type Sha2Sponge = HashSponge<Sha2Hasher>;
pub type Sha2PoW = HashPoW<Sha2Hasher>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sha2;

impl ProtocolHash for Sha2 {
    type Permutation = Sha2Permutation;
    type Sponge = Sha2Sponge;
    type MerkleConfig = Sha2MerkleConfig;
    type PoW = Sha2PoW;

    #[inline]
    fn compress(left: FieldElement, right: FieldElement) -> FieldElement {
        Sha2Hasher::compress(left, right)
    }

    fn name() -> &'static str {
        "sha2"
    }
}

crate::impl_hash_whir!(Sha2, Sha2Hasher);
