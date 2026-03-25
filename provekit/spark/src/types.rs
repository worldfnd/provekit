#[cfg(debug_assertions)]
use whir::transcript::Interaction;
use {
    provekit_common::{
        file::{
            binary_format::{SPARK_DATA_FORMAT, SPARK_DATA_VERSION},
            Compression, FileFormat, MaybeHashAware,
        },
        interner::{InternedFieldElement, Interner},
        utils::{serde_ark_vec, serde_hex},
        FieldElement, HashConfig, WhirConfig,
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

/// Compact on-disk representation of a spark matrix. Uses `Interner` for
/// value deduplication. Timestamps are omitted and recomputed on
/// deserialization.
#[derive(Serialize, Deserialize)]
pub struct CompactSparkMatrix {
    pub num_rows: usize,
    pub num_cols: usize,
    pub row:      Vec<usize>,
    pub col:      Vec<usize>,
    pub interner: Interner,
    pub val:      Vec<InternedFieldElement>,
}

impl From<SparkMatrix> for CompactSparkMatrix {
    fn from(m: SparkMatrix) -> Self {
        let num_rows = m.timestamps.final_row.len();
        let num_cols = m.timestamps.final_col.len();
        let mut interner = Interner::new();
        let val = m.coo.val.iter().map(|v| interner.intern(*v)).collect();
        Self {
            num_rows,
            num_cols,
            row: m.coo.row,
            col: m.coo.col,
            interner,
            val,
        }
    }
}

impl From<CompactSparkMatrix> for SparkMatrix {
    fn from(c: CompactSparkMatrix) -> Self {
        let row = c.row;
        let col = c.col;
        let val: Vec<FieldElement> = c
            .val
            .iter()
            .map(|&v| c.interner.get(v).expect("invalid interned value"))
            .collect();

        let len = row.len();
        let mut read_row_counters = vec![0usize; c.num_rows];
        let mut read_col_counters = vec![0usize; c.num_cols];
        let mut read_row = Vec::with_capacity(len);
        let mut read_col = Vec::with_capacity(len);

        for i in 0..len {
            read_row.push(FieldElement::from(read_row_counters[row[i]] as u64));
            read_row_counters[row[i]] += 1;
            read_col.push(FieldElement::from(read_col_counters[col[i]] as u64));
            read_col_counters[col[i]] += 1;
        }

        let final_row = read_row_counters
            .iter()
            .map(|&x| FieldElement::from(x as u64))
            .collect();
        let final_col = read_col_counters
            .iter()
            .map(|&x| FieldElement::from(x as u64))
            .collect();

        SparkMatrix {
            coo:        COOMatrix { row, col, val },
            timestamps: TimeStamps {
                read_row,
                read_col,
                final_row,
                final_col,
            },
        }
    }
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

/// Combined container for all SPARK prepared data: the R1CS matrix
/// (compact on-disk format), witnesses, and commitments.
#[derive(Serialize, Deserialize)]
pub struct SparkPreparedData {
    pub matrix:      CompactSparkMatrix,
    pub witnesses:   SerializableSparkWitnesses,
    pub commitments: SparkCommitments,
}

impl FileFormat for SparkPreparedData {
    const FORMAT: [u8; 8] = SPARK_DATA_FORMAT;
    const EXTENSION: &'static str = "spd";
    const VERSION: (u16, u16) = SPARK_DATA_VERSION;
    const COMPRESSION: Compression = Compression::Zstd;
}

/// Impl for SparkPreparedData (no hash config).
impl MaybeHashAware for SparkPreparedData {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        None
    }
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
