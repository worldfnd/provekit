//! BLAKE3-based Merkle tree configuration.

use {
    crate::FieldElement, ark_crypto_primitives::merkle_tree::Config,
    whir::crypto::merkle_tree::digest::GenericDigest,
};

pub type Blake3Digest = GenericDigest<32>;

#[derive(Clone, Debug)]
pub struct Blake3MerkleConfig;

impl Config for Blake3MerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = Blake3Digest;
    type LeafInnerDigestConverter =
        ark_crypto_primitives::merkle_tree::IdentityDigestConverter<Blake3Digest>;
    type InnerDigest = Blake3Digest;
    type LeafHash = crate::blake3::Blake3LeafHash;
    type TwoToOneHash = crate::blake3::Blake3Compress;
}

impl crate::hash_config::TypedHashConfig for Blake3MerkleConfig {
    const HASH_CONFIG: crate::HashConfig = crate::HashConfig::Blake3;
    type Sponge = crate::blake3::Blake3Sponge;
    type Unit = u8;
}
