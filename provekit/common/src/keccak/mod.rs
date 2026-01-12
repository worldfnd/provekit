//! Keccak-based hash components for ProveKit.
//!
//! - **Merkle Commitments**: Keccak256 (NIST FIPS 202)
//! - **Fiat-Shamir Transcript**: Keccak sponge (SHAKE-256 duplex construction)
//! - **Proof-of-Work**: Keccak256
//!
//! **Use Case**: NIST FIPS 202 compliance, Ethereum compatibility.

mod merkle;
mod pow;
mod sponge;
mod whir;

pub use {
    merkle::{KeccakDigest, KeccakMerkleConfig},
    pow::KeccakPoW,
    sponge::KeccakSponge,
};
