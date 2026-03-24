#[cfg(debug_assertions)]
use whir::transcript::Interaction;
use {
    provekit_common::{
        utils::{serde_ark_vec, serde_hex},
        FieldElement, WhirConfig,
    },
    serde::{Deserialize, Serialize},
    whir::{
        hash::Hash,
        protocols::{irs_commit, matrix_commit},
    },
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

pub struct SparkWitnesses {
    pub vals_witness:         WhirWitness,
    pub rs_ws_witness:        WhirWitness,
    pub final_row_ts_witness: WhirWitness,
    pub final_col_ts_witness: WhirWitness,
}

#[derive(Serialize, Deserialize)]
pub struct SerializableWhirWitness {
    #[serde(with = "serde_ark_vec")]
    matrix:               Vec<FieldElement>,
    matrix_witness:       matrix_commit::Witness,
    #[serde(with = "serde_ark_vec")]
    out_of_domain_points: Vec<FieldElement>,
    #[serde(with = "serde_ark_vec")]
    out_of_domain_matrix: Vec<FieldElement>,
}

impl From<WhirWitness> for SerializableWhirWitness {
    fn from(w: WhirWitness) -> Self {
        Self {
            matrix:               w.matrix,
            matrix_witness:       w.matrix_witness,
            out_of_domain_points: w.out_of_domain.points,
            out_of_domain_matrix: w.out_of_domain.matrix,
        }
    }
}

impl From<SerializableWhirWitness> for WhirWitness {
    fn from(s: SerializableWhirWitness) -> Self {
        Self {
            matrix:         s.matrix,
            matrix_witness: s.matrix_witness,
            out_of_domain:  irs_commit::Evaluations {
                points: s.out_of_domain_points,
                matrix: s.out_of_domain_matrix,
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SerializableSparkWitnesses {
    vals_witness:         SerializableWhirWitness,
    rs_ws_witness:        SerializableWhirWitness,
    final_row_ts_witness: SerializableWhirWitness,
    final_col_ts_witness: SerializableWhirWitness,
}

impl From<SparkWitnesses> for SerializableSparkWitnesses {
    fn from(w: SparkWitnesses) -> Self {
        Self {
            vals_witness:         w.vals_witness.into(),
            rs_ws_witness:        w.rs_ws_witness.into(),
            final_row_ts_witness: w.final_row_ts_witness.into(),
            final_col_ts_witness: w.final_col_ts_witness.into(),
        }
    }
}

impl From<SerializableSparkWitnesses> for SparkWitnesses {
    fn from(s: SerializableSparkWitnesses) -> Self {
        Self {
            vals_witness:         s.vals_witness.into(),
            rs_ws_witness:        s.rs_ws_witness.into(),
            final_row_ts_witness: s.final_row_ts_witness.into(),
            final_col_ts_witness: s.final_col_ts_witness.into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SerializableCommitment {
    pub merkle_root:          Hash,
    #[serde(with = "serde_ark_vec")]
    pub out_of_domain_points: Vec<FieldElement>,
    #[serde(with = "serde_ark_vec")]
    pub out_of_domain_evals:  Vec<FieldElement>,
}

#[derive(Serialize, Deserialize)]
pub struct SparkCommitments {
    pub vals:         SerializableCommitment,
    pub rs_ws:        SerializableCommitment,
    pub final_row_ts: SerializableCommitment,
    pub final_col_ts: SerializableCommitment,
}

/// Combined container for all SPARK prepared data: the R1CS matrix,
/// witnesses, and commitments.
#[derive(Serialize, Deserialize)]
pub struct SparkPreparedData {
    pub matrix:      SparkMatrix,
    pub witnesses:   SerializableSparkWitnesses,
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
