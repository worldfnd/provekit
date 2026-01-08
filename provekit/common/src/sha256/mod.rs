//! SHA256-based hash components for ProveKit.
//!
//! **Hybrid Configuration**: SHA256 for Merkle commitments + Skyscraper for Fiat-Shamir
//! - **Merkle Commitments**: SHA256 (NIST FIPS 180-4)
//! - **Fiat-Shamir Transcript**: Skyscraper (algebraic, field-native)
//! - **Proof-of-Work**: SHA256
//!
//! This is the **industry-standard approach** used in production ZK systems:
//! - Cryptographic hashes provide strong collision resistance for commitments
//! - Algebraic hashes provide efficient field operations for transcripts
//! - Same pattern as Ethereum 2.0, ZCash, and other production systems
//!
//! **Use Case**: Benchmarking different Merkle implementations with consistent Fiat-Shamir.

mod merkle;
mod pow;
mod sponge;
mod whir;

pub use {
    merkle::{Sha256Digest, Sha256MerkleConfig},
    pow::Sha256PoW,
    sponge::Sha256Sponge,
};
