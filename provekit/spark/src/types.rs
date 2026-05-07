use {
    provekit_common::{
        file::{
            binary_format::{
                SPARK_PROOF_FORMAT, SPARK_PROOF_VERSION, SPARK_SETUP_FORMAT, SPARK_SETUP_VERSION,
            },
            Compression, FileFormat, MaybeHashAware,
        },
        FieldElement, HashConfig, WhirConfig, WhirR1CSProof, R1CS,
    },
    serde::{Deserialize, Serialize},
    whir::protocols::irs_commit,
};

pub type WhirWitness = irs_commit::Witness<FieldElement, FieldElement>;

#[derive(Clone, Serialize, Deserialize)]
pub struct SPARKSetup {
    pub whir_params:       SPARKWHIRConfigs,
    pub matrix_dimensions: MatrixDimensions,
    pub transcript:        WhirR1CSProof,
}

impl FileFormat for SPARKSetup {
    const FORMAT: [u8; 8] = SPARK_SETUP_FORMAT;
    const EXTENSION: &'static str = "spc";
    const VERSION: (u16, u16) = SPARK_SETUP_VERSION;
    const COMPRESSION: Compression = Compression::Zstd;
}

impl MaybeHashAware for SPARKSetup {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        None
    }
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct SPARKProof(pub WhirR1CSProof);

impl FileFormat for SPARKProof {
    const FORMAT: [u8; 8] = SPARK_PROOF_FORMAT;
    const EXTENSION: &'static str = "sp";
    const VERSION: (u16, u16) = SPARK_PROOF_VERSION;
    const COMPRESSION: Compression = Compression::Zstd;
}

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
    pub num_terms_2batched: WhirConfig,
    pub num_terms_5batched: WhirConfig,
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
    pub vals_rs_ws_witness:   WhirWitness,
    pub final_row_ts_witness: WhirWitness,
    pub final_col_ts_witness: WhirWitness,
}

#[derive(Clone)]
pub struct SparkProverContext {
    pub matrix:         SparkMatrix,
    pub non_spark_r1cs: R1CS,
    pub witnesses:      SparkWitnesses,
    pub setup:          SPARKSetup,
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
