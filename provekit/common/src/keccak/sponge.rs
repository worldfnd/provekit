//! Keccak sponge for Fiat-Shamir transcripts.
//!
//! This module provides a Keccak256-based duplex sponge construction
//! for Fiat-Shamir transformations in WHIR proofs, using the SHAKE-256
//! duplex construction.

/// Keccak sponge type for Fiat-Shamir transcripts.
///
/// This is spongefish's native Keccak implementation, which uses the
/// Keccak-f[1600] permutation in duplex mode. It operates on bytes (`u8`), with
/// field elements serialized/deserialized through the spongefish arkworks
/// codecs.
///
/// - **Rate**: 136 bytes (1088 bits)
/// - **Capacity**: 64 bytes (512 bits)
/// - **Security**: 256-bit security level
pub type KeccakSponge = spongefish::keccak::Keccak;
