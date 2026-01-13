use {
    crate::{
        hash::{HashScheme, Sha2, Skyscraper},
        noir_proof_scheme::NoirProofScheme,
        whir_r1cs::WhirR1CSScheme,
    },
    serde::{Deserialize, Serialize},
};

/// A verifier for a Noir Proof Scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Verifier<H: HashScheme> {
    pub whir_for_witness: Option<WhirR1CSScheme<H>>,
}

impl<H: HashScheme> Verifier<H> {
    pub fn from_noir_proof_scheme(noir_proof_scheme: NoirProofScheme<H>) -> Self {
        Self {
            whir_for_witness: Some(noir_proof_scheme.whir_for_witness),
        }
    }
}
