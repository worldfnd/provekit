//! Pure Keccak sponge for Fiat-Shamir transcripts.
//!
//! This module provides a Keccak256-based duplex sponge construction
//! that can be used for Fiat-Shamir transformations in WHIR proofs.
//!
//! Unlike the hybrid approach (which uses Skyscraper for Fiat-Shamir),
//! this uses pure Keccak256 (SHAKE-256 duplex construction) for all operations.

/// Keccak sponge type for Fiat-Shamir transcripts.
///
/// This is spongefish's native Keccak implementation, which uses the Keccak-f[1600]
/// permutation in duplex mode. It operates on bytes (`u8`), with field elements
/// serialized/deserialized through the spongefish arkworks codecs.
///
/// - **Rate**: 136 bytes (1088 bits)
/// - **Capacity**: 64 bytes (512 bits)
/// - **Security**: 256-bit security level
/// - **Compatibility**: Ethereum-compatible (same permutation as Keccak256/SHA3)
pub type KeccakSponge = spongefish::keccak::Keccak;
