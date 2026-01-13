//! SHA256-based hash components for ProveKit.
//!
//! - **Merkle Commitments**: SHA256 (NIST FIPS 180-4)
//! - **Fiat-Shamir Transcript**: SHA256 sponge construction
//! - **Proof-of-Work**: SHA256
//!
//! **Use Case**: NIST FIPS 180-4 compliance, industry-standard cryptography.
//!
//! # Optimizations
//!
//! The `sha2` crate is configured with the `asm` feature, which provides
//! hardware-accelerated SHA256 on aarch64 (ARM) and x86_64 platforms.

mod merkle;
mod pow;
mod sponge;
mod whir;

pub use {
    merkle::{Sha256CRH, Sha256Digest, Sha256MerkleConfig, Sha256TwoToOne},
    pow::Sha256PoW,
    sponge::Sha256Sponge,
};
