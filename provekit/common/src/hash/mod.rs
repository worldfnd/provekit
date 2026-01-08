mod blake3;
mod pow;
mod sha2;
mod sha3;
mod skyscraper;
mod sponge;
mod traits;
mod utils;
mod whir;

use serde::{Deserialize, Serialize};
pub use {
    blake3::{Blake3, Blake3MerkleConfig, Blake3Permutation, Blake3PoW, Blake3Sponge},
    sha2::{Sha2, Sha2MerkleConfig, Sha2Permutation, Sha2PoW, Sha2Sponge},
    sha3::{Sha3, Sha3MerkleConfig, Sha3Permutation, Sha3PoW, Sha3Sponge},
    skyscraper::{
        Skyscraper, SkyscraperMerkleConfig, SkyscraperPermutation, SkyscraperPoW, SkyscraperSponge,
    },
    traits::ProtocolHash,
    utils::{bigint_from_bytes_le, bytes_to_field, field_to_bytes},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashFunction {
    #[default]
    Skyscraper,
    Sha2,
    Sha3,
    Blake3,
}

impl HashFunction {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "sha2" | "sha256" | "sha-256" => Self::Sha2,
            "sha3" | "sha3-256" | "sha-3" | "keccak" | "keccak256" => Self::Sha3,
            "blake3" | "blake" => Self::Blake3,
            "skyscraper" | "sky" | "default" => Self::Skyscraper,
            _ => Self::Skyscraper,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Skyscraper => "skyscraper",
            Self::Sha2 => "sha2",
            Self::Sha3 => "sha3",
            Self::Blake3 => "blake3",
        }
    }

    pub fn all_names() -> &'static [&'static str] {
        &["skyscraper", "sha2", "sha3", "blake3"]
    }
}

impl std::fmt::Display for HashFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for HashFunction {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_str(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_function_from_str() {
        assert_eq!(HashFunction::from_str("sha2"), HashFunction::Sha2);
        assert_eq!(HashFunction::from_str("SHA256"), HashFunction::Sha2);
        assert_eq!(HashFunction::from_str("sha3"), HashFunction::Sha3);
        assert_eq!(HashFunction::from_str("keccak"), HashFunction::Sha3);
        assert_eq!(HashFunction::from_str("blake3"), HashFunction::Blake3);
        assert_eq!(
            HashFunction::from_str("skyscraper"),
            HashFunction::Skyscraper
        );
        assert_eq!(HashFunction::from_str("unknown"), HashFunction::Skyscraper);
    }

    #[test]
    fn test_hash_function_roundtrip() {
        for hash in [
            HashFunction::Skyscraper,
            HashFunction::Sha2,
            HashFunction::Sha3,
            HashFunction::Blake3,
        ] {
            assert_eq!(HashFunction::from_str(hash.as_str()), hash);
        }
    }
}
