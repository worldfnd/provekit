//! Runtime-selectable Fiat-Shamir transcript sponge.
//!
//! A single enum delegates to the concrete sponge at runtime, so the spine need
//! not be generic over a sponge type parameter. The branch cost is negligible —
//! the sponge runs O(log n) times per proof, not in a tight inner loop.

use {
    provekit_common::HashConfig,
    spongefish::{instantiations, DuplexSpongeInterface},
    std::fmt,
};

/// Fiat-Shamir transcript sponge, selected at runtime by [`HashConfig`].
///
/// Delegates all [`DuplexSpongeInterface`] calls to the active variant.
#[derive(Clone)]
// Sponge states are kept inline to avoid heap indirection in the Fiat-Shamir path.
#[allow(clippy::large_enum_variant)]
pub enum TranscriptSponge {
    Sha256(instantiations::SHA256),
    Blake3(instantiations::Blake3),
    Keccak(instantiations::Keccak),
}

impl fmt::Debug for TranscriptSponge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256(_) => f.debug_tuple("Sha256").finish(),
            Self::Blake3(_) => f.debug_tuple("Blake3").finish(),
            Self::Keccak(_) => f.debug_tuple("Keccak").finish(),
        }
    }
}

impl TranscriptSponge {
    /// Create a sponge matching the given hash configuration.
    ///
    /// # Panics
    /// Panics for [`HashConfig::Skyscraper`] and [`HashConfig::Poseidon2`],
    /// which operate on 256-bit field elements and are not defined over this
    /// field.
    pub fn from_config(config: HashConfig) -> Self {
        match config {
            HashConfig::Sha256 => Self::Sha256(Default::default()),
            HashConfig::Blake3 => Self::Blake3(Default::default()),
            HashConfig::Keccak => Self::Keccak(Default::default()),
            HashConfig::Skyscraper | HashConfig::Poseidon2 => {
                panic!(
                    "HashConfig::{config:?} operates on 256-bit elements and is unsupported here"
                )
            }
        }
    }
}

impl DuplexSpongeInterface for TranscriptSponge {
    type U = u8;

    fn absorb(&mut self, input: &[u8]) -> &mut Self {
        match self {
            Self::Sha256(s) => {
                s.absorb(input);
            }
            Self::Blake3(s) => {
                s.absorb(input);
            }
            Self::Keccak(s) => {
                s.absorb(input);
            }
        }
        self
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        match self {
            Self::Sha256(s) => {
                s.squeeze(output);
            }
            Self::Blake3(s) => {
                s.squeeze(output);
            }
            Self::Keccak(s) => {
                s.squeeze(output);
            }
        }
        self
    }

    fn ratchet(&mut self) -> &mut Self {
        match self {
            Self::Sha256(s) => {
                s.ratchet();
            }
            Self::Blake3(s) => {
                s.ratchet();
            }
            Self::Keccak(s) => {
                s.ratchet();
            }
        }
        self
    }
}
