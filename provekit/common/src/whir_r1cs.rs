use {
    crate::{
        skyscraper::{SkyscraperMerkleConfig, SkyscraperPoW, SkyscraperSponge},
        utils::{serde_hex, sumcheck::SumcheckIOPattern},
        FieldElement,
    },
    serde::{Deserialize, Serialize},
    spongefish::DomainSeparator,
    std::fmt::{Debug, Formatter},
    tracing::instrument,
    whir::whir::{domainsep::WhirDomainSeparator, parameters::WhirConfig as GenericWhirConfig},
};

pub type WhirConfig = GenericWhirConfig<FieldElement, SkyscraperMerkleConfig, SkyscraperPoW>;
pub type IOPattern = DomainSeparator<SkyscraperSponge, FieldElement>;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct WhirR1CSScheme {
    pub m: usize,
    pub m_0: usize,
    pub a_num_terms: usize,
    pub whir_witness: WhirConfig,
    pub whir_for_hiding_spartan: WhirConfig,
}

impl WhirR1CSScheme {
    #[instrument(skip_all)]
    pub fn create_io_pattern(&self) -> IOPattern {
        IOPattern::new("🌪️")
            .commit_statement(&self.whir_witness)
            .add_rand(self.m_0)
            .commit_statement(&self.whir_for_hiding_spartan)
            .add_zk_sumcheck_polynomials(self.m_0)
            .add_whir_proof(&self.whir_for_hiding_spartan)
            .hint("claimed_evaluations")
            .add_whir_proof(&self.whir_witness)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhirR1CSProof {
    #[serde(with = "serde_hex")]
    pub transcript: Vec<u8>,
}

// TODO: Implement Debug for WhirConfig and derive.
impl Debug for WhirR1CSScheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhirR1CSScheme")
            .field("m", &self.m)
            .field("m_0", &self.m_0)
            .finish()
    }
}
