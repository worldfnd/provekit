// ============================================================================
// Hash Algorithm Configuration
// ============================================================================
// Default: Skyscraper
//
// Alternative configurations available via --hash flag:
use {
    crate::{
        skyscraper::{SkyscraperMerkleConfig, SkyscraperPoW, SkyscraperSponge},
        utils::{serde_hex, sumcheck::SumcheckIOPattern},
        witness::WitnessIOPattern,
        FieldElement,
    },
    serde::{Deserialize, Serialize},
    spongefish::DomainSeparator,
    std::fmt::{Debug, Formatter},
    tracing::instrument,
    whir::whir::{domainsep::WhirDomainSeparator, parameters::WhirConfig as GenericWhirConfig},
};

// Default hash configuration (Pure Skyscraper)
type CurrentMerkleConfig = SkyscraperMerkleConfig;
type CurrentPoW = SkyscraperPoW;
type CurrentSponge = SkyscraperSponge;
type CurrentDigest = FieldElement;

// Export type aliases that other crates can use
pub type CurrentMerkleConfigType = CurrentMerkleConfig;
pub type CurrentSpongeType = CurrentSponge;
pub type CurrentDigestType = CurrentDigest;
pub type CurrentUnitType = FieldElement; // Unit type for sponge (u8 for pure configs, FieldElement for Skyscraper)

// Legacy type aliases for backward compatibility
pub type WhirConfig = GenericWhirConfig<FieldElement, CurrentMerkleConfig, CurrentPoW>;
pub type IOPattern = DomainSeparator<CurrentSponge, CurrentUnitType>;

// Generic WhirR1CSScheme that works with any Merkle config and PoW strategy
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct WhirR1CSScheme<MerkleConfig = CurrentMerkleConfig, PowStrategy = CurrentPoW>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
    pub m: usize,
    pub w1_size: usize,
    pub m_0: usize,
    pub a_num_terms: usize,
    pub num_challenges: usize,
    pub whir_witness: GenericWhirConfig<FieldElement, MerkleConfig, PowStrategy>,
    pub whir_for_hiding_spartan: GenericWhirConfig<FieldElement, MerkleConfig, PowStrategy>,
}

// Default implementation for backward compatibility (uses Skyscraper)
impl WhirR1CSScheme<CurrentMerkleConfig, CurrentPoW> {
    #[instrument(skip_all)]
    pub fn create_io_pattern(&self) -> IOPattern {
        self.create_generic_io_pattern()
    }
}

// Type-specific implementations for each hash algorithm
impl WhirR1CSScheme<crate::sha256::Sha256MerkleConfig, crate::sha256::Sha256PoW> {
    #[instrument(skip_all)]
    pub fn create_io_pattern(&self) -> DomainSeparator<crate::sha256::Sha256Sponge, u8> {
        self.create_generic_io_pattern()
    }
}

impl WhirR1CSScheme<crate::keccak::KeccakMerkleConfig, crate::keccak::KeccakPoW> {
    #[instrument(skip_all)]
    pub fn create_io_pattern(&self) -> DomainSeparator<crate::keccak::KeccakSponge, u8> {
        self.create_generic_io_pattern()
    }
}

impl WhirR1CSScheme<crate::blake3::Blake3MerkleConfig, crate::blake3::Blake3PoW> {
    #[instrument(skip_all)]
    pub fn create_io_pattern(&self) -> DomainSeparator<crate::blake3::Blake3Sponge, u8> {
        self.create_generic_io_pattern()
    }
}

// Generic implementation for any sponge type
impl<MerkleConfig, PowStrategy> WhirR1CSScheme<MerkleConfig, PowStrategy>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
    #[instrument(skip_all)]
    pub fn create_generic_io_pattern<Sponge, U>(&self) -> DomainSeparator<Sponge, U>
    where
        Sponge: spongefish::duplex_sponge::DuplexSpongeInterface<U> + Clone,
        U: spongefish::Unit + Clone,
        DomainSeparator<Sponge, U>: WhirDomainSeparator<FieldElement, MerkleConfig>
            + spongefish::ByteDomainSeparator
            + spongefish::codecs::arkworks_algebra::FieldDomainSeparator<FieldElement>,
    {
        let mut io = DomainSeparator::new("🌪️");

        if self.num_challenges > 0 {
            let num_witnesses = 2;
            let num_ood_constraints = num_witnesses * self.whir_witness.committment_ood_samples;
            let num_statement_constraints = 6;
            let num_constraints_total = num_ood_constraints + num_statement_constraints;

            io = io
                .commit_statement(&self.whir_witness)
                .add_logup_challenges(self.num_challenges)
                .commit_statement(&self.whir_witness)
                .add_rand(self.m_0)
                .commit_statement(&self.whir_for_hiding_spartan)
                .add_zk_sumcheck_polynomials(self.m_0)
                .add_whir_proof(&self.whir_for_hiding_spartan)
                .hint("claimed_evaluations_1")
                .hint("claimed_evaluations_2")
                .add_whir_batch_proof(&self.whir_witness, num_witnesses, num_constraints_total);
        } else {
            io = io
                .commit_statement(&self.whir_witness)
                .add_rand(self.m_0)
                .commit_statement(&self.whir_for_hiding_spartan)
                .add_zk_sumcheck_polynomials(self.m_0)
                .add_whir_proof(&self.whir_for_hiding_spartan)
                .hint("claimed_evaluations")
                .add_whir_proof(&self.whir_witness);
        }

        io
    }

    pub fn set_reed_solomon<RS: whir::ntt::ReedSolomon<FieldElement> + 'static>(&mut self, rs: RS) {
        let rs = std::sync::Arc::new(rs);
        self.whir_witness.set_reed_solomon(rs.clone());
        self.whir_witness.set_basefield_reed_solomon(rs.clone());
        self.whir_for_hiding_spartan.set_reed_solomon(rs.clone());
        self.whir_for_hiding_spartan.set_basefield_reed_solomon(rs);
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhirR1CSProof {
    #[serde(with = "serde_hex")]
    pub transcript: Vec<u8>,
}

// TODO: Implement Debug for WhirConfig and derive.
impl<MerkleConfig, PowStrategy> Debug for WhirR1CSScheme<MerkleConfig, PowStrategy>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhirR1CSScheme")
            .field("m", &self.m)
            .field("w1_size", &self.w1_size)
            .field("m_0", &self.m_0)
            .finish()
    }
}
