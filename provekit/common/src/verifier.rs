use {
    crate::{
        noir_proof_scheme::NoirProofScheme, utils::serde_jsonify, whir_r1cs::WhirR1CSScheme,
        HashConfig, R1CS,
    },
    noirc_abi::Abi,
    serde::{Deserialize, Serialize},
};

/// On-disk **ProveKit Verifier** (PKV) — the verifier-side scheme that gets
/// serialized to a `.pkv` file by `prepare` and loaded by `verify` (or by
/// `generate-gnark-inputs` for the recursive path).
///
/// Holds the R1CS, the WHIR-for-witness commitment configuration, and the
/// ABI needed to bind public inputs back to their Noir-level names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verifier {
    pub hash_config:      HashConfig,
    pub r1cs:             R1CS,
    pub whir_for_witness: Option<WhirR1CSScheme>,
    #[serde(with = "serde_jsonify")]
    pub abi:              Abi,
    /// CanonicalSerialize'd `provekit_groth16::VerifyingKey` (None for WHIR proofs).
    #[serde(default)]
    pub groth16_vk:       Option<Vec<u8>>,
}

impl Verifier {
    pub fn from_noir_proof_scheme(scheme: NoirProofScheme) -> Self {
        match scheme {
            NoirProofScheme::Noir(d) => Self {
                r1cs:             d.r1cs,
                whir_for_witness: Some(d.whir_for_witness),
                abi:              d.witness_generator.abi.clone(),
                hash_config:      d.hash_config,
                groth16_vk:       None,
            },
            NoirProofScheme::Mavros(d) => Self {
                r1cs:             d.r1cs,
                whir_for_witness: Some(d.whir_for_witness),
                abi:              d.abi.clone(),
                hash_config:      d.hash_config,
                groth16_vk:       None,
            },
        }
    }
}
