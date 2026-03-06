use {
    crate::{
        noir_proof_scheme::NoirProofScheme, utils::serde_jsonify, whir_r1cs::WhirR1CSScheme,
        HashConfig, R1CS,
    },
    noirc_abi::Abi,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verifier {
    pub hash_config:      HashConfig,
    pub r1cs:             R1CS,
    pub whir_for_witness: Option<WhirR1CSScheme>,
    #[serde(with = "serde_jsonify")]
    pub abi:              Abi,
}

impl Verifier {
    pub fn from_noir_proof_scheme(scheme: NoirProofScheme) -> Self {
        match scheme {
            NoirProofScheme::Noir(d) => Self {
                r1cs:             d.r1cs,
                whir_for_witness: Some(d.whir_for_witness),
                abi:              d.witness_generator.abi.clone(),
                hash_config:      d.hash_config,
            },
            NoirProofScheme::Mavros(d) => Self {
                r1cs:             d.r1cs,
                whir_for_witness: Some(d.whir_for_witness),
                abi:              d.abi.clone(),
                hash_config:      d.hash_config,
            },
        }
    }
}
