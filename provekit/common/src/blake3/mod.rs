//! BLAKE3-based hash components for ProveKit.
//!
//! Provides two configurations:
//!
//! ## Hybrid Configuration (default)
//! - **Merkle Commitments**: BLAKE3 (modern, fast)
//! - **Fiat-Shamir Transcript**: Skyscraper (algebraic, field-native)
//! - **Proof-of-Work**: BLAKE3
//!
//! This is the **industry-standard approach** used in production ZK systems:
//! - Cryptographic hashes provide strong collision resistance for commitments
//! - Algebraic hashes provide efficient field operations for transcripts
//!
//! ## Pure Configuration
//! - **Merkle Commitments**: BLAKE3 (modern, fast)
//! - **Fiat-Shamir Transcript**: BLAKE3 XOF (extendable output function)
//! - **Proof-of-Work**: BLAKE3
//!
//! Pure cryptographic hash for all components. Excellent performance.
//! **Use Case**: High-performance applications, modern cryptography, benchmarking.

mod merkle;
mod pow;
mod sponge;
mod whir;

pub use {
    merkle::{Blake3Digest, Blake3MerkleConfig},
    pow::Blake3PoW,
    sponge::Blake3Sponge,
};
