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
            #[cfg(not(target_arch = "wasm32"))]
            NoirProofScheme::Mavros(d) => Self {
                r1cs:             d.r1cs,
                whir_for_witness: Some(d.whir_for_witness),
                abi:              d.abi.clone(),
                hash_config:      d.hash_config,
            },
        }
    }
}

/// Lightweight verifier for WASM environments.
///
/// Strips [`Abi`] from [`Verifier`] since it is only used for display/ABI
/// metadata and is not needed for proof verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmVerifier {
    pub hash_config:      HashConfig,
    pub r1cs:             R1CS,
    pub whir_for_witness: Option<WhirR1CSScheme>,
}

impl WasmVerifier {
    /// Create a [`WasmVerifier`] from a full [`Verifier`], discarding the
    /// ABI metadata.
    pub fn from_verifier(v: Verifier) -> Self {
        Self {
            hash_config:      v.hash_config,
            r1cs:             v.r1cs,
            whir_for_witness: v.whir_for_witness,
        }
    }
}
