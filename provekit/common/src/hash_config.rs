/// Runtime hash configuration selection for ProveKit.
///
/// This module provides runtime selection of hash algorithms, replacing
/// the previous compile-time feature flag approach.
use {
    crate::FieldElement,
    serde::{Deserialize, Serialize},
    spongefish::{
        codecs::arkworks_algebra::{
            FieldDomainSeparator, FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField,
        },
        ByteDomainSeparator, BytesToUnitDeserialize, BytesToUnitSerialize, UnitToBytes,
    },
    std::fmt,
    whir::whir::{
        domainsep::WhirDomainSeparator,
        utils::{DigestToUnitDeserialize, DigestToUnitSerialize},
    },
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
    /// assert_eq!(
    ///     HashConfig::from_str("skyscraper"),
    ///     Some(HashConfig::Skyscraper)
    /// );
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
                    "Invalid hash configuration: '{}'. Valid options: skyscraper, sha256, keccak, \
                     blake3",
                    name
                )
            }
        }
    }
}

impl std::error::Error for HashConfigError {}

/// Trait for types that have an associated HashConfig.
/// This allows us to derive the hash configuration from generic type parameters
/// rather than storing it as a field.
pub trait TypedHashConfig {
    /// The hash configuration for this type.
    const HASH_CONFIG: HashConfig;

    /// The sponge type used for Fiat-Shamir transcripts.
    type Sponge: spongefish::duplex_sponge::DuplexSpongeInterface<Self::Unit> + Clone + 'static;

    /// The unit type used by the sponge.
    type Unit: spongefish::Unit + Clone + 'static;
}

/// Trait alias for MerkleConfig bounds required by WHIR.
pub trait WhirMerkleConfig:
    ark_crypto_primitives::merkle_tree::Config<Leaf = [FieldElement]>
    + TypedHashConfig
    + Clone
    + 'static
where
    ark_crypto_primitives::merkle_tree::LeafParam<Self>: Clone,
    ark_crypto_primitives::merkle_tree::TwoToOneParam<Self>: Clone,
{
}

impl<T> WhirMerkleConfig for T
where
    T: ark_crypto_primitives::merkle_tree::Config<Leaf = [FieldElement]>
        + TypedHashConfig
        + Clone
        + 'static,
    ark_crypto_primitives::merkle_tree::LeafParam<T>: Clone,
    ark_crypto_primitives::merkle_tree::TwoToOneParam<T>: Clone,
{
}

/// Trait alias for `ProverState` bounds required by WHIR proving.
pub trait WhirProverState<M: ark_crypto_primitives::merkle_tree::Config>:
    FieldToUnitSerialize<FieldElement>
    + UnitToField<FieldElement>
    + BytesToUnitSerialize
    + UnitToBytes
    + DigestToUnitSerialize<M>
{
}

impl<T, M> WhirProverState<M> for T
where
    M: ark_crypto_primitives::merkle_tree::Config,
    T: FieldToUnitSerialize<FieldElement>
        + UnitToField<FieldElement>
        + BytesToUnitSerialize
        + UnitToBytes
        + DigestToUnitSerialize<M>,
{
}

/// Trait alias for `VerifierState` bounds required by WHIR verification.
pub trait WhirVerifierState<M: ark_crypto_primitives::merkle_tree::Config>:
    FieldToUnitDeserialize<FieldElement>
    + UnitToField<FieldElement>
    + BytesToUnitDeserialize
    + UnitToBytes
    + DigestToUnitDeserialize<M>
{
}

impl<T, M> WhirVerifierState<M> for T
where
    M: ark_crypto_primitives::merkle_tree::Config,
    T: FieldToUnitDeserialize<FieldElement>
        + UnitToField<FieldElement>
        + BytesToUnitDeserialize
        + UnitToBytes
        + DigestToUnitDeserialize<M>,
{
}

/// Trait alias for `DomainSeparator` bounds required by WHIR.
pub trait WhirDomainSep<M: ark_crypto_primitives::merkle_tree::Config>:
    WhirDomainSeparator<FieldElement, M> + ByteDomainSeparator + FieldDomainSeparator<FieldElement>
{
}

impl<T, M> WhirDomainSep<M> for T
where
    M: ark_crypto_primitives::merkle_tree::Config,
    T: WhirDomainSeparator<FieldElement, M>
        + ByteDomainSeparator
        + FieldDomainSeparator<FieldElement>,
{
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_names() {
        assert_eq!(
            HashConfig::from_str("skyscraper"),
            Some(HashConfig::Skyscraper)
        );
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
