#[cfg(debug_assertions)]
use whir::transcript::Interaction;
use {
    provekit_common::{
        file::{
            binary_format::{
                SPARK_COMMITMENTS_FORMAT, SPARK_COMMITMENTS_VERSION, SPARK_PROOF_FORMAT,
                SPARK_PROOF_VERSION,
            },
            Compression, FileFormat, MaybeHashAware,
        },
        utils::{serde_ark, serde_hex},
        FieldElement, HashConfig, WhirConfig,
    },
    serde::{Deserialize, Serialize},
    whir::{hash::Hash, protocols::irs_commit},
};

pub type WhirWitness = irs_commit::Witness<FieldElement, FieldElement>;

#[derive(Serialize, Deserialize)]
pub struct SPARKProof {
    #[serde(with = "serde_hex")]
    pub narg_string:       Vec<u8>,
    #[serde(with = "serde_hex")]
    pub hints:             Vec<u8>,
    #[cfg(debug_assertions)]
    pub pattern:           Vec<Interaction>,
    pub whir_params:       SPARKWHIRConfigs,
    pub matrix_dimensions: MatrixDimensions,
}

impl FileFormat for SPARKProof {
    const FORMAT: [u8; 8] = SPARK_PROOF_FORMAT;
    const EXTENSION: &'static str = "sp";
    const VERSION: (u16, u16) = SPARK_PROOF_VERSION;
    const COMPRESSION: Compression = Compression::Zstd;
}

/// Impl for SPARKProof (no hash config).
impl MaybeHashAware for SPARKProof {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        None
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MatrixDimensions {
    pub num_rows:      usize,
    pub num_cols:      usize,
    pub nonzero_terms: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SPARKWHIRConfigs {
    pub row:                WhirConfig,
    pub col:                WhirConfig,
    pub num_terms_1batched: WhirConfig,
    pub num_terms_2batched: WhirConfig,
    pub num_terms_4batched: WhirConfig,
}

#[derive(Debug, Clone)]
pub struct SparkMatrix {
    pub coo:        COOMatrix,
    pub timestamps: TimeStamps,
}

#[derive(Debug, Clone)]
pub struct COOMatrix {
    pub row:       Vec<usize>,
    pub col:       Vec<usize>,
    pub row_field: Vec<FieldElement>,
    pub col_field: Vec<FieldElement>,
    pub val:       Vec<FieldElement>,
}

#[derive(Debug, Clone)]
pub struct TimeStamps {
    pub read_row:  Vec<FieldElement>,
    pub read_col:  Vec<FieldElement>,
    pub final_row: Vec<FieldElement>,
    pub final_col: Vec<FieldElement>,
}

#[derive(Clone)]
pub struct SparkWitnesses {
    pub vals_witness:         WhirWitness,
    pub rs_ws_witness:        WhirWitness,
    pub final_row_ts_witness: WhirWitness,
    pub final_col_ts_witness: WhirWitness,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SerializableCommitment {
    pub merkle_root:          Hash,
    #[serde(with = "serde_ark")]
    pub out_of_domain_points: Vec<FieldElement>,
    #[serde(with = "serde_ark")]
    pub out_of_domain_evals:  Vec<FieldElement>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SparkCommitments {
    pub vals:         SerializableCommitment,
    pub rs_ws:        SerializableCommitment,
    pub final_row_ts: SerializableCommitment,
    pub final_col_ts: SerializableCommitment,
}

impl FileFormat for SparkCommitments {
    const FORMAT: [u8; 8] = SPARK_COMMITMENTS_FORMAT;
    const EXTENSION: &'static str = "spc";
    const VERSION: (u16, u16) = SPARK_COMMITMENTS_VERSION;
    const COMPRESSION: Compression = Compression::Zstd;
}

impl MaybeHashAware for SparkCommitments {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        None
    }
}

/// All data needed for SPARK proving: the R1CS matrix, witnesses, and
/// commitments.
#[derive(Clone)]
pub struct SparkPreparedData {
    pub matrix:      SparkMatrix,
    pub witnesses:   SparkWitnesses,
    pub commitments: SparkCommitments,
}

#[derive(Debug, Clone)]
pub struct Memory {
    pub eq_rx: Vec<FieldElement>,
    pub eq_ry: Vec<FieldElement>,
}

#[derive(Debug, Clone)]
pub struct EValuesForMatrix {
    pub e_rx: Vec<FieldElement>,
    pub e_ry: Vec<FieldElement>,
}

/// Challenges drawn from the Fiat-Shamir transcript during proving.
#[derive(Debug, Clone)]
pub struct Challenges {
    pub gamma: FieldElement,
    pub tau:   FieldElement,
}
