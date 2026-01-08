//! BLAKE3-based Merkle tree configuration.
//!
//! Uses WHIR's built-in BLAKE3 implementation for Merkle commitments.

use {
    crate::FieldElement,
    ark_crypto_primitives::merkle_tree::Config,
    whir::crypto::merkle_tree::{
        blake3::{Blake3Compress, Blake3LeafHash},
        digest::GenericDigest,
    },
};

/// 32-byte BLAKE3 digest.
pub type Blake3Digest = GenericDigest<32>;

/// BLAKE3-based Merkle tree configuration for ProveKit.
///
/// This uses BLAKE3 for both leaf and inner node hashing.
#[derive(Clone, Debug)]
pub struct Blake3MerkleConfig;

impl Config for Blake3MerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = Blake3Digest;
    type LeafInnerDigestConverter = ark_crypto_primitives::merkle_tree::IdentityDigestConverter<Blake3Digest>;
    type InnerDigest = Blake3Digest;
    type LeafHash = Blake3LeafHash<FieldElement>;
    type TwoToOneHash = Blake3Compress;
}
