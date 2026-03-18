#[cfg(debug_assertions)]
use whir::transcript::Interaction;
use {
    provekit_common::{
        utils::{serde_ark_vec, serde_hex},
        FieldElement, WhirConfig,
    },
    serde::{Deserialize, Serialize},
    whir::protocols::irs_commit,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparkMatrix {
    pub coo:        COOMatrix,
    pub timestamps: TimeStamps,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct COOMatrix {
    pub row: Vec<usize>,
    pub col: Vec<usize>,
    #[serde(with = "serde_ark_vec")]
    pub val: Vec<FieldElement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeStamps {
    #[serde(with = "serde_ark_vec")]
    pub read_row:  Vec<FieldElement>,
    #[serde(with = "serde_ark_vec")]
    pub read_col:  Vec<FieldElement>,
    #[serde(with = "serde_ark_vec")]
    pub final_row: Vec<FieldElement>,
    #[serde(with = "serde_ark_vec")]
    pub final_col: Vec<FieldElement>,
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
