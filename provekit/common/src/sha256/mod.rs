//! SHA256-based hash components for ProveKit.
//!
//! - **Merkle Commitments**: SHA256 (NIST FIPS 180-4)
//! - **Fiat-Shamir Transcript**: SHA256 sponge construction
//! - **Proof-of-Work**: SHA256
//!
//! **Use Case**: NIST FIPS 180-4 compliance, industry-standard cryptography.

mod merkle;
mod pow;
mod sponge;
mod whir;

pub use {
    merkle::{Sha256Digest, Sha256MerkleConfig},
    pow::Sha256PoW,
    sponge::Sha256Sponge,
};
