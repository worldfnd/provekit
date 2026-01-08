//! Pure BLAKE3 sponge for Fiat-Shamir transcripts.
//!
//! This module provides a BLAKE3-based duplex sponge construction
//! that can be used for Fiat-Shamir transformations in WHIR proofs.
//!
//! Unlike the hybrid approach (which uses Skyscraper for Fiat-Shamir),
//! this uses pure BLAKE3 for all operations, leveraging its extendable
//! output function (XOF) capabilities.

use {
    blake3,
    spongefish::duplex_sponge::DuplexSpongeInterface,
    zeroize::Zeroize,
};

/// BLAKE3 duplex sponge for Fiat-Shamir transcripts.
///
/// This provides a duplex sponge construction using BLAKE3's XOF mode.
/// BLAKE3 is a modern, fast cryptographic hash function with excellent
/// performance characteristics.
///
/// - **Performance**: Typically faster than SHA256 and Keccak
/// - **Security**: 256-bit security level
/// - **XOF**: Extendable output function for arbitrary-length outputs
#[derive(Clone)]
pub struct Blake3Sponge {
    /// Current hasher state for absorbing
    hasher: blake3::Hasher,
    /// Cached output for squeezing
    output_reader: Option<blake3::OutputReader>,
    /// Mode: true = absorbing, false = squeezing
    absorbing: bool,
}

impl Default for Blake3Sponge {
    fn default() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            output_reader: None,
            absorbing: true,
        }
    }
}

impl DuplexSpongeInterface<u8> for Blake3Sponge {
    fn new(iv: [u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&iv);
        Self {
            hasher,
            output_reader: None,
            absorbing: true,
        }
    }

    fn absorb_unchecked(&mut self, input: &[u8]) -> &mut Self {
        // If we were squeezing, finalize that phase and restart
        if !self.absorbing {
            // Ratchet: hash the previous state to get a new starting point
            let prev_hash = if let Some(ref mut reader) = self.output_reader {
                let mut buf = [0u8; 32];
                reader.fill(&mut buf);
                buf
            } else {
                *self.hasher.finalize().as_bytes()
            };

            self.hasher = blake3::Hasher::new();
            self.hasher.update(&prev_hash);
            self.output_reader = None;
            self.absorbing = true;
        }

        self.hasher.update(input);
        self
    }

    fn squeeze_unchecked(&mut self, output: &mut [u8]) -> &mut Self {
        // If we were absorbing, switch to squeezing mode
        if self.absorbing {
            self.output_reader = Some(self.hasher.finalize_xof());
            self.absorbing = false;
        }

        if let Some(ref mut reader) = self.output_reader {
            reader.fill(output);
        }
        self
    }

    fn ratchet_unchecked(&mut self) -> &mut Self {
        // Finalize current state and restart with the hash as seed
        let hash = if let Some(ref mut reader) = self.output_reader {
            let mut buf = [0u8; 32];
            reader.fill(&mut buf);
            buf
        } else {
            *self.hasher.finalize().as_bytes()
        };

        self.hasher = blake3::Hasher::new();
        self.hasher.update(&hash);
        self.output_reader = None;
        self.absorbing = true;
        self
    }
}

impl Zeroize for Blake3Sponge {
    fn zeroize(&mut self) {
        self.hasher = blake3::Hasher::new();
        self.output_reader = None;
        self.absorbing = true;
    }
}
