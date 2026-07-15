use {
    crate::{spark::SparkSetup, Bn254Field, FieldElement, NoirProofScheme},
    noirc_abi::Abi,
    provekit_common::{utils::serde_jsonify, HashConfig, WhirR1CSScheme, R1CS},
    serde::{Deserialize, Serialize},
};

/// On-disk **ProveKit Verifier** (PKV) — the verifier-side scheme that gets
/// serialized to a `.pkv` file by `prepare` and loaded by `verify` (or by
/// `generate-gnark-inputs` for the recursive path).
///
/// Holds the R1CS, the WHIR-for-witness commitment configuration, the SPARK
/// setup (when `prepare --spark` was used), and the ABI needed to bind public
/// inputs back to their Noir-level names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verifier {
    pub hash_config:      HashConfig,
    pub r1cs:             R1CS<FieldElement>,
    pub whir_for_witness: Option<WhirR1CSScheme<Bn254Field>>,
    pub spark_setup:      Option<SparkSetup>,
    #[serde(with = "serde_jsonify")]
    pub abi:              Abi,
}

impl Verifier {
    pub fn from_noir_proof_scheme(scheme: NoirProofScheme) -> Self {
        match scheme {
            NoirProofScheme::Noir(d) => Self {
                r1cs:             d.r1cs,
                whir_for_witness: Some(d.whir_for_witness),
                spark_setup:      None,
                abi:              d.witness_generator.abi.clone(),
                hash_config:      d.hash_config,
            },
            NoirProofScheme::Mavros(d) => Self {
                r1cs:             d.r1cs,
                whir_for_witness: Some(d.whir_for_witness),
                spark_setup:      None,
                abi:              d.abi.clone(),
                hash_config:      d.hash_config,
            },
        }
    }
}
