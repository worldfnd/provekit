use {
    crate::{noir_proof_scheme::NoirProofScheme, whir_r1cs::WhirR1CSScheme},
    serde::{Deserialize, Serialize},
};

/// A verifier for a Noir Proof Scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verifier {
    pub whir_for_witness: Option<WhirR1CSScheme>,
    pub whir_for_w1:      Option<WhirR1CSScheme>,
}

impl Verifier {
    pub fn from_noir_proof_scheme(noir_proof_scheme: NoirProofScheme) -> Self {
        Self {
            whir_for_witness: Some(noir_proof_scheme.whir_for_witness),
            whir_for_w1:      Some(noir_proof_scheme.whir_for_w1),
        }
    }
}
