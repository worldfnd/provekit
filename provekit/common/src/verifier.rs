use {
    crate::{
        noir_proof_scheme::NoirProofScheme, utils::serde_jsonify, whir_r1cs::WhirR1CSScheme, R1CS,
    },
    noirc_abi::Abi,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verifier {
    pub r1cs:             R1CS,
    pub whir_for_witness: Option<WhirR1CSScheme>,
    #[serde(with = "serde_jsonify")]
    pub abi:              Abi,
}

impl Verifier {
    pub fn from_noir_proof_scheme(noir_proof_scheme: NoirProofScheme) -> Self {
        Self {
            r1cs:             noir_proof_scheme.r1cs,
            whir_for_witness: Some(noir_proof_scheme.whir_for_witness),
            abi:              noir_proof_scheme.witness_generator.abi.clone(),
        }
    }
}
