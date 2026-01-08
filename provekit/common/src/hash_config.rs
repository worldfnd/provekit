/// Runtime hash configuration selection for ProveKit.
///
/// This module provides runtime selection of hash algorithms, replacing
/// the previous compile-time feature flag approach.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Hash algorithm configuration that can be selected at runtime.
///
/// Each variant uses the **same hash** for both:
/// - **Merkle tree commitments**: Binds polynomial data
/// - **Fiat-Shamir transcript**: Interactive proof made non-interactive
/// - **Proof of Work**: Optional computational puzzle
///
/// All configurations are "pure" (not hybrid).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashConfig {
    /// Skyscraper (algebraic hash) for all components.
    ///
    /// - **Merkle**: Skyscraper (~10-15 constraints/hash)
    /// - **Fiat-Shamir**: Skyscraper sponge
    /// - **PoW**: Skyscraper
    ///
    /// **Best for**: ZK-optimized performance (default)
    /// **Type**: Algebraic hash
    #[serde(alias = "sky")]
    Skyscraper,

    /// SHA256 for all components.
    ///
    /// - **Merkle**: SHA256 (~2000 constraints/hash)
    /// - **Fiat-Shamir**: SHA256 sponge construction
    /// - **PoW**: SHA256
    ///
    /// **Best for**: NIST FIPS 180-4 compliance
    /// **Type**: Cryptographic hash (NIST standard)
    #[serde(alias = "sha", alias = "sha-256")]
    Sha256,

    /// Keccak for all components.
    ///
    /// - **Merkle**: Keccak (~2000 constraints/hash)
    /// - **Fiat-Shamir**: Keccak sponge (SHAKE-256)
    /// - **PoW**: Keccak
    ///
    /// **Best for**: NIST FIPS 202 compliance, Ethereum compatibility
    /// **Type**: Cryptographic sponge (NIST standard)
    #[serde(alias = "keccak-256", alias = "shake")]
    Keccak,

    /// BLAKE3 for all components.
    ///
    /// - **Merkle**: BLAKE3 (~1500 constraints/hash)
    /// - **Fiat-Shamir**: BLAKE3 XOF (extendable output)
    /// - **PoW**: BLAKE3
    ///
    /// **Best for**: Modern cryptography, fastest cryptographic hash
    /// **Type**: Cryptographic hash (modern, not NIST standardized)
    #[serde(alias = "blake-3", alias = "b3")]
    Blake3,
}

impl HashConfig {
    /// Returns the canonical name of this hash configuration.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Skyscraper => "skyscraper",
            Self::Sha256 => "sha256",
            Self::Keccak => "keccak",
            Self::Blake3 => "blake3",
        }
    }

    /// Returns a short description of this configuration.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Skyscraper => "Algebraic hash (fastest for ZK)",
            Self::Sha256 => "SHA256 (NIST FIPS 180-4)",
            Self::Keccak => "Keccak/SHAKE-256 (NIST FIPS 202)",
            Self::Blake3 => "BLAKE3 (modern, fast)",
        }
    }

    /// Returns whether this configuration uses algebraic hashes.
    pub fn is_algebraic(&self) -> bool {
        matches!(self, Self::Skyscraper)
    }

    /// Returns whether this configuration uses cryptographic hashes.
    pub fn is_cryptographic(&self) -> bool {
        !self.is_algebraic()
    }

    /// Parses a hash configuration from a string.
    ///
    /// # Examples
    ///
    /// ```
    /// use provekit_common::HashConfig;
    ///
    /// assert_eq!(HashConfig::from_str("skyscraper"), Some(HashConfig::Skyscraper));
    /// assert_eq!(HashConfig::from_str("sha256"), Some(HashConfig::Sha256));
    /// assert_eq!(HashConfig::from_str("keccak"), Some(HashConfig::Keccak));
    /// assert_eq!(HashConfig::from_str("blake3"), Some(HashConfig::Blake3));
    /// assert_eq!(HashConfig::from_str("invalid"), None);
    /// ```
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "skyscraper" | "sky" => Some(Self::Skyscraper),
            "sha256" | "sha" | "sha-256" => Some(Self::Sha256),
            "keccak" | "keccak-256" | "shake" => Some(Self::Keccak),
            "blake3" | "blake-3" | "b3" => Some(Self::Blake3),
            _ => None,
        }
    }

    /// Returns all available hash configurations.
    pub fn all() -> &'static [Self] {
        &[Self::Skyscraper, Self::Sha256, Self::Keccak, Self::Blake3]
    }
}

impl Default for HashConfig {
    fn default() -> Self {
        Self::Skyscraper
    }
}

impl fmt::Display for HashConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for HashConfig {
    type Err = HashConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s).ok_or_else(|| HashConfigError::InvalidName(s.to_string()))
    }
}

/// Error type for hash configuration parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashConfigError {
    /// Invalid hash configuration name.
    InvalidName(String),
}

impl fmt::Display for HashConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(name) => {
                write!(
                    f,
                    "Invalid hash configuration: '{}'. Valid options: skyscraper, sha256, keccak, blake3",
                    name
                )
            }
        }
    }
}

impl std::error::Error for HashConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_names() {
        assert_eq!(HashConfig::from_str("skyscraper"), Some(HashConfig::Skyscraper));
        assert_eq!(HashConfig::from_str("sky"), Some(HashConfig::Skyscraper));
        assert_eq!(HashConfig::from_str("sha256"), Some(HashConfig::Sha256));
        assert_eq!(HashConfig::from_str("sha"), Some(HashConfig::Sha256));
        assert_eq!(HashConfig::from_str("keccak"), Some(HashConfig::Keccak));
        assert_eq!(HashConfig::from_str("shake"), Some(HashConfig::Keccak));
        assert_eq!(HashConfig::from_str("blake3"), Some(HashConfig::Blake3));
        assert_eq!(HashConfig::from_str("b3"), Some(HashConfig::Blake3));
        assert_eq!(HashConfig::from_str("invalid"), None);
    }

    #[test]
    fn test_properties() {
        assert!(HashConfig::Skyscraper.is_algebraic());
        assert!(!HashConfig::Skyscraper.is_cryptographic());

        assert!(!HashConfig::Sha256.is_algebraic());
        assert!(HashConfig::Sha256.is_cryptographic());

        assert!(!HashConfig::Keccak.is_algebraic());
        assert!(HashConfig::Keccak.is_cryptographic());

        assert!(!HashConfig::Blake3.is_algebraic());
        assert!(HashConfig::Blake3.is_cryptographic());
    }

    #[test]
    fn test_serialization() {
        let config = HashConfig::Sha256;
        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(json, r#""sha256""#);

        let parsed: HashConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, config);
    }
}
