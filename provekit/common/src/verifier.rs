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
    pub fn from_noir_proof_scheme(scheme: NoirProofScheme) -> Self {
        match scheme {
            NoirProofScheme::Noir(d) => Self {
                r1cs:             d.r1cs,
                whir_for_witness: Some(d.whir_for_witness),
            },
            NoirProofScheme::Mavros(d) => Self {
                r1cs:             d.r1cs,
                whir_for_witness: Some(d.whir_for_witness),
            },
        }
    }
}
