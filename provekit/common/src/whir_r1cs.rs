use {
    crate::{utils::serde_hex, FieldElement},
    serde::{Deserialize, Serialize},
    std::fmt::{Debug, Formatter},
    whir::{protocols::whir::Config as GenericWhirConfig, transcript},
};

pub type WhirConfig = GenericWhirConfig<FieldElement>;

/// Type alias for the whir domain separator used in provekit's outer protocol.
pub type WhirDomainSeparator = transcript::DomainSeparator<'static, ()>;

/// Type alias for the whir prover transcript state.
pub type WhirProverState = transcript::ProverState;

/// Type alias for the whir proof.
pub type WhirProof = transcript::Proof;

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
    /// Create a domain separator for the provekit outer protocol.
    ///
    /// The whir transcript derives its IO pattern from the config hash,
    /// so we create a domain separator from the scheme config.
    pub fn create_domain_separator(&self) -> WhirDomainSeparator {
        transcript::DomainSeparator::protocol(self)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhirR1CSProof {
    #[serde(with = "serde_hex")]
    pub narg_string: Vec<u8>,
    #[serde(with = "serde_hex")]
    pub hints:       Vec<u8>,
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
