/// Runtime hash configuration selection for ProveKit.
///
/// This module provides runtime selection of hash algorithms. The selected
/// hash is used for Merkle tree commitments (via WHIR's `EngineId`) and
/// the Fiat-Shamir transcript sponge (via [`crate::TranscriptSponge`]).
use {
    serde::{Deserialize, Serialize},
    std::fmt,
};

/// Hash algorithm configuration that can be selected at runtime.
///
/// Each variant uses the same hash algorithm for:
/// - **Merkle tree commitments**: Binds polynomial data
/// - **Fiat-Shamir transcript**: Interactive proof made non-interactive
/// - **Proof of Work**: Optional computational puzzle
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashConfig {
    #[serde(alias = "sky")]
    Skyscraper,

    #[serde(alias = "sha", alias = "sha-256")]
    Sha256,

    #[serde(alias = "keccak-256", alias = "shake")]
    Keccak,

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

    /// Returns the WHIR 2.0 engine ID for this hash configuration.
    pub fn engine_id(&self) -> whir::engines::EngineId {
        match self {
            Self::Skyscraper => crate::skyscraper::SKYSCRAPER,
            Self::Sha256 => whir::hash::SHA2,
            Self::Keccak => whir::hash::KECCAK,
            Self::Blake3 => whir::hash::BLAKE3,
        }
    }

    /// Converts hash configuration to a single byte for binary file headers.
    pub fn to_byte(&self) -> u8 {
        match self {
            Self::Skyscraper => 0,
            Self::Sha256 => 1,
            Self::Keccak => 2,
            Self::Blake3 => 3,
        }
    }

    /// Converts a byte from binary file header to hash configuration.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Skyscraper),
            1 => Some(Self::Sha256),
            2 => Some(Self::Keccak),
            3 => Some(Self::Blake3),
            _ => None,
        }
    }

    /// Parses a hash configuration from a string.
    pub fn parse(s: &str) -> Option<Self> {
        let lower = s.to_lowercase();
        match lower.as_str() {
            "skyscraper" | "sky" => Some(Self::Skyscraper),
            "sha256" | "sha" | "sha-256" => Some(Self::Sha256),
            "keccak" | "keccak-256" | "shake" => Some(Self::Keccak),
            "blake3" | "blake-3" | "b3" => Some(Self::Blake3),
            _ => None,
        }
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
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| {
            format!(
                "Invalid hash configuration: '{}'. Valid options: skyscraper, sha256, keccak, \
                 blake3",
                s
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All known variants. If a new variant is added to `HashConfig`, this
    /// list must be updated — causing the exhaustiveness tests below to fail
    /// until `from_byte` / `to_byte` are also updated.
    const ALL_VARIANTS: &[HashConfig] = &[
        HashConfig::Skyscraper,
        HashConfig::Sha256,
        HashConfig::Keccak,
        HashConfig::Blake3,
    ];

    #[test]
    fn from_byte_roundtrips_with_to_byte() {
        for &variant in ALL_VARIANTS {
            let byte = variant.to_byte();
            let recovered = HashConfig::from_byte(byte)
                .unwrap_or_else(|| panic!("from_byte({byte}) returned None for {variant:?}"));
            assert_eq!(variant, recovered, "roundtrip failed for {variant:?}");
        }
    }

    #[test]
    fn from_byte_returns_none_for_invalid() {
        // One past the last valid byte, and a large value.
        let first_invalid = ALL_VARIANTS.len() as u8;
        assert!(
            HashConfig::from_byte(first_invalid).is_none(),
            "from_byte({first_invalid}) should be None"
        );
        assert!(
            HashConfig::from_byte(u8::MAX).is_none(),
            "from_byte(255) should be None"
        );
    }

    #[test]
    fn to_byte_values_are_contiguous_from_zero() {
        let mut bytes: Vec<u8> = ALL_VARIANTS.iter().map(|v| v.to_byte()).collect();
        bytes.sort();
        let expected: Vec<u8> = (0..ALL_VARIANTS.len() as u8).collect();
        assert_eq!(bytes, expected, "to_byte values should be 0..N contiguous");
    }

    #[test]
    fn from_byte_covers_all_variants() {
        // Collect every Some value from from_byte over the full u8 range.
        let recovered: Vec<HashConfig> = (0..=u8::MAX).filter_map(HashConfig::from_byte).collect();
        for &variant in ALL_VARIANTS {
            assert!(
                recovered.contains(&variant),
                "{variant:?} is not reachable via from_byte"
            );
        }
        assert_eq!(
            recovered.len(),
            ALL_VARIANTS.len(),
            "from_byte maps to more variants than ALL_VARIANTS lists"
        );
    }
}
