//! Runtime-selectable Fiat-Shamir transcript sponge.
//!
//! A single enum dispatches to the concrete sponge chosen by `HashConfig`,
//! instead of threading a sponge type parameter through every function.
//! Field-native sponges (Skyscraper, Poseidon2) sit behind the `DynFieldSponge`
//! shim; byte sponges use `spongefish`'s instantiations directly.

use {
    crate::{
        field::{provider, DynFieldSponge},
        HashConfig,
    },
    spongefish::{instantiations, DuplexSpongeInterface},
    std::fmt,
};

/// Fiat-Shamir transcript sponge, selected at runtime by [`HashConfig`].
///
/// Delegates all [`DuplexSpongeInterface`] calls to the active variant.
pub enum TranscriptSponge {
    Sha256(instantiations::SHA256),
    Blake3(instantiations::Blake3),
    Keccak(instantiations::Keccak),
    /// Field-native sponge (Skyscraper or Poseidon2).
    Field(Box<dyn DynFieldSponge>),
}

impl Clone for TranscriptSponge {
    fn clone(&self) -> Self {
        match self {
            Self::Sha256(s) => Self::Sha256(s.clone()),
            Self::Blake3(s) => Self::Blake3(s.clone()),
            Self::Keccak(s) => Self::Keccak(s.clone()),
            Self::Field(s) => Self::Field(s.clone_box()),
        }
    }
}

impl fmt::Debug for TranscriptSponge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256(_) => f.debug_tuple("Sha256").finish(),
            Self::Blake3(_) => f.debug_tuple("Blake3").finish(),
            Self::Keccak(_) => f.debug_tuple("Keccak").finish(),
            Self::Field(_) => f.debug_tuple("Field").finish(),
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
            HashConfig::Skyscraper | HashConfig::Poseidon2 => {
                Self::Field(provider().field_sponge(config))
            }
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
        // Qualify byte-sponge calls: the blanket `DynFieldSponge` impl is also
        // in scope, so a bare `s.absorb(..)` would be ambiguous.
        match self {
            Self::Sha256(s) => {
                DuplexSpongeInterface::absorb(s, input);
            }
            Self::Blake3(s) => {
                DuplexSpongeInterface::absorb(s, input);
            }
            Self::Keccak(s) => {
                DuplexSpongeInterface::absorb(s, input);
            }
            Self::Field(s) => {
                s.absorb(input);
            }
        }
        self
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        match self {
            Self::Sha256(s) => {
                DuplexSpongeInterface::squeeze(s, output);
            }
            Self::Blake3(s) => {
                DuplexSpongeInterface::squeeze(s, output);
            }
            Self::Keccak(s) => {
                DuplexSpongeInterface::squeeze(s, output);
            }
            Self::Field(s) => {
                s.squeeze(output);
            }
        }
        self
    }

    fn ratchet(&mut self) -> &mut Self {
        match self {
            Self::Sha256(s) => {
                DuplexSpongeInterface::ratchet(s);
            }
            Self::Blake3(s) => {
                DuplexSpongeInterface::ratchet(s);
            }
            Self::Keccak(s) => {
                DuplexSpongeInterface::ratchet(s);
            }
            Self::Field(s) => {
                s.ratchet();
            }
        }
        self
    }
}
