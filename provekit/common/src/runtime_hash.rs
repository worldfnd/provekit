//! Runtime hash selection for WHIR proofs.
//!
//! This module provides runtime dispatch for different hash configurations,
//! enabling benchmarking and comparison of hash algorithms without recompilation.

use crate::{
    blake3::{Blake3Digest, Blake3MerkleConfig, Blake3PoW, Blake3Sponge},
    keccak::{KeccakDigest, KeccakMerkleConfig, KeccakPoW, KeccakSponge},
    sha256::{Sha256Digest, Sha256MerkleConfig, Sha256PoW},
    skyscraper::{SkyscraperMerkleConfig, SkyscraperPoW},
    FieldElement, HashConfig,
};
use whir::whir::parameters::WhirConfig as GenericWhirConfig;

// ============================================================================
// Hash-specific type aliases - Hybrid Configurations
// ============================================================================

/// WHIR configuration for Skyscraper (pure algebraic)
pub type SkyscraperWhirConfig =
    GenericWhirConfig<FieldElement, SkyscraperMerkleConfig, SkyscraperPoW>;

/// WHIR configuration for SHA256 (hybrid: SHA256 Merkle + Skyscraper Fiat-Shamir)
pub type Sha256WhirConfig = GenericWhirConfig<FieldElement, Sha256MerkleConfig, Sha256PoW>;

/// WHIR configuration for Keccak (hybrid: Keccak Merkle + Skyscraper Fiat-Shamir)
pub type KeccakWhirConfig = GenericWhirConfig<FieldElement, KeccakMerkleConfig, KeccakPoW>;

/// WHIR configuration for BLAKE3 (hybrid: BLAKE3 Merkle + Skyscraper Fiat-Shamir)
pub type Blake3WhirConfig = GenericWhirConfig<FieldElement, Blake3MerkleConfig, Blake3PoW>;

// ============================================================================
// Pure Configurations (same hash for Merkle + Fiat-Shamir)
// ============================================================================

/// WHIR configuration for pure Keccak (Keccak for both Merkle and Fiat-Shamir)
///
/// Use with: `DomainSeparator<KeccakSponge, u8>`
///
/// Example:
/// ```ignore
/// use provekit_common::{KeccakPureWhirConfig, keccak::KeccakSponge};
/// use spongefish::DomainSeparator;
///
/// type IOPattern = DomainSeparator<KeccakSponge, u8>;
/// ```
pub type KeccakPureWhirConfig = GenericWhirConfig<FieldElement, KeccakMerkleConfig, KeccakPoW>;

/// WHIR configuration for pure BLAKE3 (BLAKE3 for both Merkle and Fiat-Shamir)
///
/// Use with: `DomainSeparator<Blake3Sponge, u8>`
///
/// Example:
/// ```ignore
/// use provekit_common::{Blake3PureWhirConfig, blake3::Blake3Sponge};
/// use spongefish::DomainSeparator;
///
/// type IOPattern = DomainSeparator<Blake3Sponge, u8>;
/// ```
pub type Blake3PureWhirConfig = GenericWhirConfig<FieldElement, Blake3MerkleConfig, Blake3PoW>;

// ============================================================================
// Runtime dispatch enums
// ============================================================================

/// Runtime-dispatched WHIR configuration supporting all hash algorithms.
///
/// This allows selecting hash algorithm at runtime for benchmarking and comparison.
#[derive(Clone)]
pub enum WhirConfigAny {
    Skyscraper(SkyscraperWhirConfig),
    Sha256(Sha256WhirConfig),
    Keccak(KeccakWhirConfig),
    Blake3(Blake3WhirConfig),
}

impl WhirConfigAny {
    /// Returns the hash configuration used by this WHIR config.
    pub fn hash_config(&self) -> HashConfig {
        match self {
            Self::Skyscraper(_) => HashConfig::Skyscraper,
            Self::Sha256(_) => HashConfig::Sha256,
            Self::Keccak(_) => HashConfig::Keccak,
            Self::Blake3(_) => HashConfig::Blake3,
        }
    }

    /// Get the security level.
    pub fn security_level(&self) -> usize {
        match self {
            Self::Skyscraper(c) => c.security_level,
            Self::Sha256(c) => c.security_level,
            Self::Keccak(c) => c.security_level,
            Self::Blake3(c) => c.security_level,
        }
    }

    /// Get the max PoW bits.
    pub fn max_pow_bits(&self) -> usize {
        match self {
            Self::Skyscraper(c) => c.max_pow_bits,
            Self::Sha256(c) => c.max_pow_bits,
            Self::Keccak(c) => c.max_pow_bits,
            Self::Blake3(c) => c.max_pow_bits,
        }
    }

    /// Get the commitment OOD samples.
    pub fn committment_ood_samples(&self) -> usize {
        match self {
            Self::Skyscraper(c) => c.committment_ood_samples,
            Self::Sha256(c) => c.committment_ood_samples,
            Self::Keccak(c) => c.committment_ood_samples,
            Self::Blake3(c) => c.committment_ood_samples,
        }
    }

    /// Get the starting log inverse rate.
    pub fn starting_log_inv_rate(&self) -> usize {
        match self {
            Self::Skyscraper(c) => c.starting_log_inv_rate,
            Self::Sha256(c) => c.starting_log_inv_rate,
            Self::Keccak(c) => c.starting_log_inv_rate,
            Self::Blake3(c) => c.starting_log_inv_rate,
        }
    }
}

/// Runtime-dispatched Merkle digest supporting all hash algorithms.
#[derive(Clone, Debug, PartialEq)]
pub enum DigestAny {
    Skyscraper(FieldElement),
    Sha256(Sha256Digest),
    Keccak(KeccakDigest),
    Blake3(Blake3Digest),
}

impl DigestAny {
    /// Returns the hash configuration used by this digest.
    pub fn hash_config(&self) -> HashConfig {
        match self {
            Self::Skyscraper(_) => HashConfig::Skyscraper,
            Self::Sha256(_) => HashConfig::Sha256,
            Self::Keccak(_) => HashConfig::Keccak,
            Self::Blake3(_) => HashConfig::Blake3,
        }
    }
}

// ============================================================================
// Runtime dispatch for ProveKit types
// ============================================================================

use crate::{
    noir_proof_scheme::NoirProofScheme,
    prover::Prover,
    verifier::Verifier,
};
use serde::{Deserialize, Serialize};

/// Runtime-dispatched NoirProofScheme supporting all hash algorithms.
///
/// This allows the proof scheme to be loaded with the correct hash types
/// at runtime based on the --hash flag.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "hash_type")]
pub enum NoirProofSchemeAny {
    #[serde(rename = "skyscraper")]
    Skyscraper(NoirProofScheme<SkyscraperMerkleConfig, SkyscraperPoW>),
    #[serde(rename = "sha256")]
    Sha256(NoirProofScheme<Sha256MerkleConfig, Sha256PoW>),
    #[serde(rename = "keccak")]
    Keccak(NoirProofScheme<KeccakMerkleConfig, KeccakPoW>),
    #[serde(rename = "blake3")]
    Blake3(NoirProofScheme<Blake3MerkleConfig, Blake3PoW>),
}

impl std::fmt::Debug for NoirProofSchemeAny {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Skyscraper(s) => f.debug_tuple("Skyscraper").field(s).finish(),
            Self::Sha256(s) => f.debug_tuple("Sha256").field(s).finish(),
            Self::Keccak(_) => f.debug_tuple("Keccak").field(&"<NoirProofScheme>").finish(),
            Self::Blake3(_) => f.debug_tuple("Blake3").field(&"<NoirProofScheme>").finish(),
        }
    }
}

impl NoirProofSchemeAny {
    /// Returns the hash configuration.
    pub fn hash_config(&self) -> HashConfig {
        match self {
            Self::Skyscraper(s) => s.hash_config,
            Self::Sha256(s) => s.hash_config,
            Self::Keccak(s) => s.hash_config,
            Self::Blake3(s) => s.hash_config,
        }
    }

    /// Returns the circuit size (constraints, witnesses).
    pub fn size(&self) -> (usize, usize) {
        match self {
            Self::Skyscraper(s) => s.size(),
            Self::Sha256(s) => s.size(),
            Self::Keccak(s) => s.size(),
            Self::Blake3(s) => s.size(),
        }
    }
}

/// Runtime-dispatched Prover supporting all hash algorithms.
///
/// This allows the prover to use the correct hash implementation
/// at runtime based on how the scheme was prepared.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "hash_type")]
pub enum ProverAny {
    #[serde(rename = "skyscraper")]
    Skyscraper(Prover<SkyscraperMerkleConfig, SkyscraperPoW>),
    #[serde(rename = "sha256")]
    Sha256(Prover<Sha256MerkleConfig, Sha256PoW>),
    #[serde(rename = "keccak")]
    Keccak(Prover<KeccakMerkleConfig, KeccakPoW>),
    #[serde(rename = "blake3")]
    Blake3(Prover<Blake3MerkleConfig, Blake3PoW>),
}

impl std::fmt::Debug for ProverAny {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Skyscraper(p) => f.debug_tuple("Skyscraper").field(p).finish(),
            Self::Sha256(p) => f.debug_tuple("Sha256").field(p).finish(),
            Self::Keccak(_) => f.debug_tuple("Keccak").field(&"<Prover>").finish(),
            Self::Blake3(_) => f.debug_tuple("Blake3").field(&"<Prover>").finish(),
        }
    }
}

impl ProverAny {
    /// Returns the hash configuration.
    pub fn hash_config(&self) -> HashConfig {
        match self {
            Self::Skyscraper(p) => p.hash_config,
            Self::Sha256(p) => p.hash_config,
            Self::Keccak(p) => p.hash_config,
            Self::Blake3(p) => p.hash_config,
        }
    }

    /// Returns the circuit size (constraints, witnesses).
    pub fn size(&self) -> (usize, usize) {
        match self {
            Self::Skyscraper(p) => p.size(),
            Self::Sha256(p) => p.size(),
            Self::Keccak(p) => p.size(),
            Self::Blake3(p) => p.size(),
        }
    }
}

/// Runtime-dispatched Verifier supporting all hash algorithms.
///
/// This allows the verifier to use the correct hash implementation
/// at runtime based on how the scheme was prepared.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "hash_type")]
pub enum VerifierAny {
    #[serde(rename = "skyscraper")]
    Skyscraper(Verifier<SkyscraperMerkleConfig, SkyscraperPoW>),
    #[serde(rename = "sha256")]
    Sha256(Verifier<Sha256MerkleConfig, Sha256PoW>),
    #[serde(rename = "keccak")]
    Keccak(Verifier<KeccakMerkleConfig, KeccakPoW>),
    #[serde(rename = "blake3")]
    Blake3(Verifier<Blake3MerkleConfig, Blake3PoW>),
}

impl std::fmt::Debug for VerifierAny {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Skyscraper(v) => f.debug_tuple("Skyscraper").field(v).finish(),
            Self::Sha256(v) => f.debug_tuple("Sha256").field(v).finish(),
            Self::Keccak(_) => f.debug_tuple("Keccak").field(&"<Verifier>").finish(),
            Self::Blake3(_) => f.debug_tuple("Blake3").field(&"<Verifier>").finish(),
        }
    }
}

impl VerifierAny {
    /// Returns the hash configuration.
    pub fn hash_config(&self) -> HashConfig {
        match self {
            Self::Skyscraper(v) => v.hash_config,
            Self::Sha256(v) => v.hash_config,
            Self::Keccak(v) => v.hash_config,
            Self::Blake3(v) => v.hash_config,
        }
    }
}

// ============================================================================
// Runtime conversion helpers
// ============================================================================

impl NoirProofSchemeAny {
    /// Convert to ProverAny.
    pub fn to_prover(self) -> ProverAny {
        match self {
            Self::Skyscraper(s) => ProverAny::Skyscraper(Prover::from_noir_proof_scheme(s)),
            Self::Sha256(s) => ProverAny::Sha256(Prover::from_noir_proof_scheme(s)),
            Self::Keccak(s) => ProverAny::Keccak(Prover::from_noir_proof_scheme(s)),
            Self::Blake3(s) => ProverAny::Blake3(Prover::from_noir_proof_scheme(s)),
        }
    }

    /// Convert to VerifierAny.
    pub fn to_verifier(self) -> VerifierAny {
        match self {
            Self::Skyscraper(s) => VerifierAny::Skyscraper(Verifier::from_noir_proof_scheme(s)),
            Self::Sha256(s) => VerifierAny::Sha256(Verifier::from_noir_proof_scheme(s)),
            Self::Keccak(s) => VerifierAny::Keccak(Verifier::from_noir_proof_scheme(s)),
            Self::Blake3(s) => VerifierAny::Blake3(Verifier::from_noir_proof_scheme(s)),
        }
    }
}
