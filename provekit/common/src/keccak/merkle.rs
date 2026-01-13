//! Keccak-based Merkle tree configuration.

use {
    crate::FieldElement,
    ark_crypto_primitives::merkle_tree::Config,
    whir::crypto::merkle_tree::digest::GenericDigest,
};

pub type KeccakDigest = GenericDigest<32>;

#[derive(Clone, Debug)]
pub struct KeccakMerkleConfig;

impl Config for KeccakMerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = KeccakDigest;
    type LeafInnerDigestConverter =
        ark_crypto_primitives::merkle_tree::IdentityDigestConverter<KeccakDigest>;
    type InnerDigest = KeccakDigest;
    type LeafHash = crate::keccak::Keccak256LeafHash;
    type TwoToOneHash = crate::keccak::Keccak256Compress;
}

impl crate::hash_config::TypedHashConfig for KeccakMerkleConfig {
    const HASH_CONFIG: crate::HashConfig = crate::HashConfig::Keccak;
    type Sponge = crate::keccak::KeccakSponge;
    type Unit = u8;
}
