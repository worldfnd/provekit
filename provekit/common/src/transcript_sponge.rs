//! Runtime-selectable Fiat-Shamir transcript sponge.
//!
//! Instead of making every function generic over a sponge type parameter,
//! we use a single enum that delegates to the concrete sponge at runtime.
//! The branch cost is negligible — the sponge is called O(log n) times
//! per proof for Fiat-Shamir challenges, not in a tight inner loop.

#[cfg(feature = "bn254")]
use crate::{poseidon2::Poseidon2Sponge, skyscraper::SkyscraperSponge};
use {
    crate::HashConfig,
    spongefish::{instantiations, DuplexSpongeInterface},
    std::fmt,
};

/// Fiat-Shamir transcript sponge, selected at runtime by [`HashConfig`].
///
/// Delegates all [`DuplexSpongeInterface`] calls to the active variant.
#[derive(Clone)]
pub enum TranscriptSponge {
    Sha256(instantiations::SHA256),
    Blake3(instantiations::Blake3),
    Keccak(instantiations::Keccak),
    #[cfg(feature = "bn254")]
    Skyscraper(SkyscraperSponge),
    #[cfg(feature = "bn254")]
    Poseidon2(Poseidon2Sponge),
}

impl fmt::Debug for TranscriptSponge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256(_) => f.debug_tuple("Sha256").finish(),
            Self::Blake3(_) => f.debug_tuple("Blake3").finish(),
            Self::Keccak(_) => f.debug_tuple("Keccak").finish(),
            #[cfg(feature = "bn254")]
            Self::Skyscraper(_) => f.debug_tuple("Skyscraper").finish(),
            #[cfg(feature = "bn254")]
            Self::Poseidon2(_) => f.debug_tuple("Poseidon2").finish(),
        }
    }
}

impl TranscriptSponge {
    /// Create a sponge matching the given hash configuration.
    pub fn from_config(config: HashConfig) -> Self {
        match config {
            HashConfig::Sha256 => Self::Sha256(Default::default()),
            HashConfig::Blake3 => Self::Blake3(Default::default()),
            HashConfig::Keccak => Self::Keccak(Default::default()),
            #[cfg(feature = "bn254")]
            HashConfig::Skyscraper => Self::Skyscraper(Default::default()),
            #[cfg(feature = "bn254")]
            HashConfig::Poseidon2 => Self::Poseidon2(Default::default()),
        }
    }
}

impl Default for TranscriptSponge {
    fn default() -> Self {
        Self::from_config(HashConfig::default())
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
            #[cfg(feature = "bn254")]
            Self::Skyscraper(s) => {
                s.absorb(input);
            }
            #[cfg(feature = "bn254")]
            Self::Poseidon2(s) => {
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
            #[cfg(feature = "bn254")]
            Self::Skyscraper(s) => {
                s.squeeze(output);
            }
            #[cfg(feature = "bn254")]
            Self::Poseidon2(s) => {
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
            #[cfg(feature = "bn254")]
            Self::Skyscraper(s) => {
                s.ratchet();
            }
            #[cfg(feature = "bn254")]
            Self::Poseidon2(s) => {
                s.ratchet();
            }
        }
        self
    }
}
