use {
    crate::{
        noir_proof_scheme::NoirProofScheme,
        whir_r1cs::WhirR1CSScheme,
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        HashConfig, NoirElement, R1CS,
    },
    acir::circuit::Program,
    serde::{Deserialize, Serialize},
};

/// A prover for a Noir Proof Scheme
/// Generic over MerkleConfig and PowStrategy to support different hash algorithms.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Prover<MerkleConfig = crate::skyscraper::SkyscraperMerkleConfig, PowStrategy = crate::skyscraper::SkyscraperPoW>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    pub whir_for_witness:       WhirR1CSScheme<MerkleConfig, PowStrategy>,
    /// Hash configuration for Merkle trees and Fiat-Shamir transcript
    #[serde(default)]
    pub hash_config:            HashConfig,
}

impl<MerkleConfig, PowStrategy> Prover<MerkleConfig, PowStrategy>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
    pub fn from_noir_proof_scheme(noir_proof_scheme: NoirProofScheme<MerkleConfig, PowStrategy>) -> Self {
        Self {
            program:                noir_proof_scheme.program,
            r1cs:                   noir_proof_scheme.r1cs,
            split_witness_builders: noir_proof_scheme.split_witness_builders,
            witness_generator:      noir_proof_scheme.witness_generator,
            whir_for_witness:       noir_proof_scheme.whir_for_witness,
            hash_config:            noir_proof_scheme.hash_config,
        }
    }

    pub const fn size(&self) -> (usize, usize) {
        (self.r1cs.num_constraints(), self.r1cs.num_witnesses())
    }
}
