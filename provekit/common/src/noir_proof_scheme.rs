use {
    crate::{
        skyscraper::{SkyscraperMerkleConfig, SkyscraperPoW},
        whir_r1cs::{WhirR1CSProof, WhirR1CSScheme},
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        HashConfig, NoirElement, R1CS,
    },
    acir::circuit::Program,
    serde::{Deserialize, Serialize},
};

/// A scheme for proving a Noir program.
/// Generic over MerkleConfig and PowStrategy to support different hash
/// algorithms.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct NoirProofScheme<MerkleConfig = SkyscraperMerkleConfig, PowStrategy = SkyscraperPoW>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    pub whir_for_witness:       WhirR1CSScheme<MerkleConfig, PowStrategy>,
    pub hash_config:            HashConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoirProof {
    pub whir_r1cs_proof: WhirR1CSProof,
}

impl<MerkleConfig, PowStrategy> NoirProofScheme<MerkleConfig, PowStrategy>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
    #[must_use]
    pub const fn size(&self) -> (usize, usize) {
        (self.r1cs.num_constraints(), self.r1cs.num_witnesses())
    }
}
