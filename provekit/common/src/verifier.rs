use {
    crate::{noir_proof_scheme::NoirProofScheme, whir_r1cs::WhirR1CSScheme, R1CS},
    serde::{Deserialize, Serialize},
};

/// A verifier for a Noir Proof Scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verifier {
    pub r1cs:             R1CS,
    pub whir_for_witness: Option<WhirR1CSScheme>,
}

impl Verifier {
    pub fn from_noir_proof_scheme(noir_proof_scheme: NoirProofScheme) -> Self {
        Self {
            r1cs:             noir_proof_scheme.r1cs,
            whir_for_witness: Some(noir_proof_scheme.whir_for_witness),
        }
    }
}
