use {
    crate::{
        hash_config::TypedHashConfig,
        lazy_r1cs::LazyR1CS,
        noir_proof_scheme::NoirProofScheme,
        whir_r1cs::WhirR1CSScheme,
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        HashConfig, NoirElement,
    },
    acir::circuit::Program,
    serde::{Deserialize, Serialize},
};

/// A prover for a Noir Proof Scheme
/// Generic over MerkleConfig and PowStrategy to support different hash
/// algorithms.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Prover<
    MerkleConfig = crate::skyscraper::SkyscraperMerkleConfig,
    PowStrategy = crate::skyscraper::SkyscraperPoW,
> where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
    pub hash_config:            HashConfig,
    pub program:                Program<NoirElement>,
    pub r1cs:                   LazyR1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    pub whir_for_witness:       WhirR1CSScheme<MerkleConfig, PowStrategy>,
}

impl<MerkleConfig, PowStrategy> Prover<MerkleConfig, PowStrategy>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config + TypedHashConfig,
{
    pub fn from_noir_proof_scheme(
        noir_proof_scheme: NoirProofScheme<MerkleConfig, PowStrategy>,
    ) -> Self {
        Self {
            hash_config:            MerkleConfig::HASH_CONFIG,
            program:                noir_proof_scheme.program,
            r1cs:                   LazyR1CS::from_r1cs(noir_proof_scheme.r1cs),
            split_witness_builders: noir_proof_scheme.split_witness_builders,
            witness_generator:      noir_proof_scheme.witness_generator,
            whir_for_witness:       noir_proof_scheme.whir_for_witness,
        }
    }

    pub const fn size(&self) -> (usize, usize) {
        (self.r1cs.num_constraints(), self.r1cs.num_witnesses())
    }

    pub fn set_reed_solomon<RS: whir::ntt::ReedSolomon<crate::FieldElement> + 'static>(
        &mut self,
        rs: RS,
    ) {
        self.whir_for_witness.set_reed_solomon(rs);
    }
}
