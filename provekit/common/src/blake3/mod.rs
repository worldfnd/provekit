//! BLAKE3-based hash components for ProveKit.
//!
//! - **Merkle Commitments**: BLAKE3 (modern, fast)
//! - **Fiat-Shamir Transcript**: BLAKE3 XOF (extendable output function)
//! - **Proof-of-Work**: BLAKE3
//!
//! **Use Case**: High-performance applications, modern cryptography.

mod merkle;
mod pow;
mod sponge;
mod whir;

pub use {
    merkle::{Blake3Digest, Blake3MerkleConfig},
    pow::Blake3PoW,
    sponge::Blake3Sponge,
};
