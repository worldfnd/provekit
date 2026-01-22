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

pub type WhirConfig = GenericWhirConfig<FieldElement, SkyscraperMerkleConfig, SkyscraperPoW>;
pub type IOPattern = DomainSeparator<SkyscraperSponge, FieldElement>;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct WhirR1CSScheme {
    pub m: usize,
    pub w1_size: usize,
    pub m_0: usize,
    pub a_num_terms: usize,
    pub num_challenges: usize,
    pub has_public_inputs: bool,
    pub whir_witness: WhirConfig,
    pub whir_for_hiding_spartan: WhirConfig,
}

impl WhirR1CSScheme {
    #[instrument(skip_all)]
    pub fn create_io_pattern(&self) -> IOPattern {
        let mut io = IOPattern::new("🌪️");

        if self.num_challenges > 0 {
            // Compute total constraints: OOD + statement
            // OOD: 2 witnesses × committment_ood_samples each
            // Statement: statement_1 has 3 constraints + 1 public weights constraint = 4,
            // statement_2 has 3 constraints = 3, total = 7
            let num_witnesses = 2;
            let num_ood_constraints = num_witnesses * self.whir_witness.committment_ood_samples;
            let num_statement_constraints = if self.has_public_inputs { 7 } else { 6 };
            let num_constraints_total = num_ood_constraints + num_statement_constraints;

            io = io
                .commit_statement(&self.whir_witness) // C1
                .add_logup_challenges(self.num_challenges)
                .commit_statement(&self.whir_witness) // C2
                .add_rand(self.m_0)
                .commit_statement(&self.whir_for_hiding_spartan)
                .add_zk_sumcheck_polynomials(self.m_0)
                .add_whir_proof(&self.whir_for_hiding_spartan)
                .add_public_inputs()
                .hint("claimed_evaluations_1")
                .hint("claimed_evaluations_2")
                .hint("public_weights_evaluations")
                .add_whir_batch_proof(&self.whir_witness, num_witnesses, num_constraints_total);
        } else {
            io = io
                .commit_statement(&self.whir_witness)
                .add_rand(self.m_0)
                .commit_statement(&self.whir_for_hiding_spartan)
                .add_zk_sumcheck_polynomials(self.m_0)
                .add_whir_proof(&self.whir_for_hiding_spartan)
                .add_public_inputs()
                .hint("claimed_evaluations")
                .hint("public_weights_evaluations")
                .add_whir_proof(&self.whir_witness);
        }

        io
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
            .field("w1_size", &self.w1_size)
            .field("m_0", &self.m_0)
            .finish()
    }
}
