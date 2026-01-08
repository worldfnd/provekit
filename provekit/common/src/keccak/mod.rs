//! Keccak-based hash components for ProveKit.
//!
//! Provides two configurations:
//!
//! ## Hybrid Configuration (default)
//! - **Merkle Commitments**: Keccak256 (NIST FIPS 202)
//! - **Fiat-Shamir Transcript**: Skyscraper (algebraic, field-native)
//! - **Proof-of-Work**: Keccak256
//!
//! This is the **industry-standard approach** used in production ZK systems:
//! - Cryptographic hashes provide strong collision resistance for commitments
//! - Algebraic hashes provide efficient field operations for transcripts
//!
//! ## Pure Configuration
//! - **Merkle Commitments**: Keccak256 (NIST FIPS 202)
//! - **Fiat-Shamir Transcript**: Keccak sponge (SHAKE-256 duplex construction)
//! - **Proof-of-Work**: Keccak256
//!
//! Pure cryptographic hash for all components. Ethereum-compatible.
//! **Use Case**: Ethereum compatibility, NIST FIPS 202 compliance, benchmarking.

mod merkle;
mod pow;
mod sponge;
mod whir;

pub use {
    merkle::{KeccakDigest, KeccakMerkleConfig},
    pow::KeccakPoW,
    sponge::KeccakSponge,
};
