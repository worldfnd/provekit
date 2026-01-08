//! Keccak-based Merkle tree configuration.
//!
//! Uses WHIR's built-in Keccak256 implementation for Merkle commitments.

use {
    crate::FieldElement,
    ark_crypto_primitives::merkle_tree::Config,
    whir::crypto::merkle_tree::{
        digest::GenericDigest,
        keccak::{KeccakCompress, KeccakLeafHash},
    },
};

/// 32-byte Keccak256 digest.
pub type KeccakDigest = GenericDigest<32>;

/// Keccak-based Merkle tree configuration for ProveKit.
///
/// This uses Keccak256 (Ethereum-compatible) for both leaf and inner node hashing.
#[derive(Clone, Debug)]
pub struct KeccakMerkleConfig;

impl Config for KeccakMerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = KeccakDigest;
    type LeafInnerDigestConverter = ark_crypto_primitives::merkle_tree::IdentityDigestConverter<KeccakDigest>;
    type InnerDigest = KeccakDigest;
    type LeafHash = KeccakLeafHash<FieldElement>;
    type TwoToOneHash = KeccakCompress;
}
