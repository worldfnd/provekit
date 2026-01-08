use {
    crate::{noir_proof_scheme::NoirProofScheme, whir_r1cs::WhirR1CSScheme, HashConfig},
    serde::{Deserialize, Serialize},
};

/// A verifier for a Noir Proof Scheme
/// Generic over MerkleConfig and PowStrategy to support different hash algorithms.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Verifier<MerkleConfig = crate::skyscraper::SkyscraperMerkleConfig, PowStrategy = crate::skyscraper::SkyscraperPoW>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
    pub whir_for_witness: Option<WhirR1CSScheme<MerkleConfig, PowStrategy>>,
    /// Hash configuration for Merkle trees and Fiat-Shamir transcript
    #[serde(default)]
    pub hash_config:      HashConfig,
}

impl<MerkleConfig, PowStrategy> Verifier<MerkleConfig, PowStrategy>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
    pub fn from_noir_proof_scheme(noir_proof_scheme: NoirProofScheme<MerkleConfig, PowStrategy>) -> Self {
        Self {
            whir_for_witness: Some(noir_proof_scheme.whir_for_witness),
            hash_config:      noir_proof_scheme.hash_config,
        }
    }
}
