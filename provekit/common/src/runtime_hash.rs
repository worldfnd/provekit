//! Runtime hash selection for WHIR proofs.
//!
//! This module provides runtime dispatch for different hash configurations,
//! enabling benchmarking and comparison of hash algorithms without
//! recompilation.

use {crate::FieldElement, whir::whir::parameters::WhirConfig as GenericWhirConfig};

// ============================================================================
// Hash-specific type aliases
// ============================================================================

/// WHIR configuration for Skyscraper.
pub type SkyscraperWhirConfig = GenericWhirConfig<
    FieldElement,
    crate::skyscraper::SkyscraperMerkleConfig,
    crate::skyscraper::SkyscraperPoW,
>;

/// WHIR configuration for SHA256.
pub type Sha256WhirConfig =
    GenericWhirConfig<FieldElement, crate::sha256::Sha256MerkleConfig, crate::sha256::Sha256PoW>;

/// WHIR configuration for Keccak.
pub type KeccakWhirConfig =
    GenericWhirConfig<FieldElement, crate::keccak::KeccakMerkleConfig, crate::keccak::KeccakPoW>;

/// WHIR configuration for BLAKE3.
pub type Blake3WhirConfig =
    GenericWhirConfig<FieldElement, crate::blake3::Blake3MerkleConfig, crate::blake3::Blake3PoW>;

// ============================================================================
// Runtime dispatch macro
// ============================================================================

/// Dispatch on hash configuration at runtime.
///
/// # Examples
///
/// ```ignore
/// use provekit_common::{runtime_hash, HashConfig};
///
/// let hash_config = HashConfig::Sha256;
/// let result = runtime_hash!(hash_config, |MerkleConfig, PowStrategy| {
///     // Code here is monomorphized for each hash type
///     // MerkleConfig and PowStrategy are concrete types based on hash_config
///     create_scheme::<MerkleConfig, PowStrategy>()
/// });
/// ```
#[macro_export]
macro_rules! runtime_hash {
    ($hash_config:expr, | $merkle:ident, $pow:ident | $body:expr) => {
        match $hash_config {
            $crate::HashConfig::Skyscraper => {
                type $merkle = $crate::skyscraper::SkyscraperMerkleConfig;
                type $pow = $crate::skyscraper::SkyscraperPoW;
                $body
            }
            $crate::HashConfig::Sha256 => {
                type $merkle = $crate::sha256::Sha256MerkleConfig;
                type $pow = $crate::sha256::Sha256PoW;
                $body
            }
            $crate::HashConfig::Keccak => {
                type $merkle = $crate::keccak::KeccakMerkleConfig;
                type $pow = $crate::keccak::KeccakPoW;
                $body
            }
            $crate::HashConfig::Blake3 => {
                type $merkle = $crate::blake3::Blake3MerkleConfig;
                type $pow = $crate::blake3::Blake3PoW;
                $body
            }
        }
    };
}
