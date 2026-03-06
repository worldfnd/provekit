#[cfg(debug_assertions)]
use std::fmt::Debug;
#[cfg(debug_assertions)]
use whir::transcript::Interaction;
use {
    crate::{utils::serde_hex, FieldElement},
    serde::{Deserialize, Serialize},
    whir::{
        algebra::embedding::Identity,
        protocols::{whir::Config as GenericWhirConfig, whir_zk::Config as GenericWhirZkConfig},
        transcript,
    },
};

pub type WhirConfig = GenericWhirConfig<Identity<FieldElement>>;
pub type WhirZkConfig = GenericWhirZkConfig<FieldElement>;

/// Type alias for the whir domain separator used in provekit's outer protocol.
type WhirDomainSeparator = transcript::DomainSeparator<'static, ()>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhirR1CSScheme {
    pub m:                 usize,
    pub w1_size:           usize,
    pub m_0:               usize,
    pub a_num_terms:       usize,
    pub num_challenges:    usize,
    pub has_public_inputs: bool,
    pub whir_witness:      WhirZkConfig,
}

impl WhirR1CSScheme {
    /// Create a domain separator for the provekit outer protocol.
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

    /// Transcript interaction pattern for debug-mode validation.
    /// Populated by the prover; absent from serialized proofs on disk.
    #[cfg(debug_assertions)]
    #[serde(skip)]
    pub pattern: Vec<Interaction>,
}
