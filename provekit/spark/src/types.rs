pub use provekit_backend_bn254::{MatrixDimensions, SparkSetup, SparkWhirConfigs};
use {
    provekit_backend_bn254::FieldElement,
    provekit_common::{
        file::{
            binary_format::{
                SPARK_CONTEXT_FORMAT, SPARK_CONTEXT_VERSION, SPARK_PROOF_FORMAT,
                SPARK_PROOF_VERSION,
            },
            Compression, FileFormat, MaybeHashAware,
        },
        utils::serde_ark_vec,
        HashConfig, WhirR1CSProof,
    },
    serde::{Deserialize, Serialize},
    whir::protocols::irs_commit,
};

pub type WhirWitness = irs_commit::Witness<FieldElement, FieldElement>;

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct SparkProof(pub WhirR1CSProof);

impl FileFormat for SparkProof {
    const FORMAT: [u8; 8] = SPARK_PROOF_FORMAT;
    const EXTENSION: &'static str = "sp";
    const VERSION: (u16, u16) = SPARK_PROOF_VERSION;
    const COMPRESSION: Compression = Compression::Zstd;
}

impl MaybeHashAware for SparkProof {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "SparkMatrixSerde", into = "SparkMatrixSerde")]
pub struct SparkMatrix {
    pub coo:        COOMatrix,
    pub timestamps: TimeStamps,
}

impl SparkMatrix {
    pub fn new(
        row: Vec<usize>,
        col: Vec<usize>,
        val: Vec<FieldElement>,
        num_rows: usize,
        num_cols: usize,
    ) -> Self {
        let len = row.len();
        let mut read_row_counters = vec![0u32; num_rows];
        let mut read_col_counters = vec![0u32; num_cols];
        let mut read_row = Vec::with_capacity(len);
        let mut read_col = Vec::with_capacity(len);
        for i in 0..len {
            read_row.push(read_row_counters[row[i]]);
            read_row_counters[row[i]] += 1;
            read_col.push(read_col_counters[col[i]]);
            read_col_counters[col[i]] += 1;
        }
        Self {
            coo:        COOMatrix { row, col, val },
            timestamps: TimeStamps {
                read_row,
                read_col,
                final_row: read_row_counters,
                final_col: read_col_counters,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct COOMatrix {
    pub row: Vec<usize>,
    pub col: Vec<usize>,
    pub val: Vec<FieldElement>,
}

impl COOMatrix {
    pub fn row_field(&self) -> Vec<FieldElement> {
        self.row
            .iter()
            .map(|&r| FieldElement::from(r as u64))
            .collect()
    }

    pub fn col_field(&self) -> Vec<FieldElement> {
        self.col
            .iter()
            .map(|&c| FieldElement::from(c as u64))
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct TimeStamps {
    pub read_row:  Vec<u32>,
    pub read_col:  Vec<u32>,
    pub final_row: Vec<u32>,
    pub final_col: Vec<u32>,
}

impl TimeStamps {
    pub fn read_row_field(&self) -> Vec<FieldElement> {
        self.read_row
            .iter()
            .map(|&x| FieldElement::from(u64::from(x)))
            .collect()
    }

    pub fn read_col_field(&self) -> Vec<FieldElement> {
        self.read_col
            .iter()
            .map(|&x| FieldElement::from(u64::from(x)))
            .collect()
    }

    pub fn final_row_field(&self) -> Vec<FieldElement> {
        self.final_row
            .iter()
            .map(|&x| FieldElement::from(u64::from(x)))
            .collect()
    }

    pub fn final_col_field(&self) -> Vec<FieldElement> {
        self.final_col
            .iter()
            .map(|&x| FieldElement::from(u64::from(x)))
            .collect()
    }
}

#[derive(Serialize, Deserialize)]
struct SparkMatrixSerde {
    row:      Vec<usize>,
    col:      Vec<usize>,
    #[serde(with = "serde_ark_vec")]
    val:      Vec<FieldElement>,
    num_rows: usize,
    num_cols: usize,
}

impl From<SparkMatrix> for SparkMatrixSerde {
    fn from(m: SparkMatrix) -> Self {
        Self {
            num_rows: m.timestamps.final_row.len(),
            num_cols: m.timestamps.final_col.len(),
            row:      m.coo.row,
            col:      m.coo.col,
            val:      m.coo.val,
        }
    }
}

impl From<SparkMatrixSerde> for SparkMatrix {
    fn from(s: SparkMatrixSerde) -> Self {
        SparkMatrix::new(s.row, s.col, s.val, s.num_rows, s.num_cols)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SparkWitnesses {
    #[serde(with = "crate::serde_whir_witness")]
    pub vals_rs_ws_witness:   WhirWitness,
    #[serde(with = "crate::serde_whir_witness")]
    pub final_row_ts_witness: WhirWitness,
    #[serde(with = "crate::serde_whir_witness")]
    pub final_col_ts_witness: WhirWitness,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SparkProverContext {
    pub matrix:    SparkMatrix,
    pub witnesses: SparkWitnesses,
    pub setup:     SparkSetup,
}

impl FileFormat for SparkProverContext {
    const FORMAT: [u8; 8] = SPARK_CONTEXT_FORMAT;
    const EXTENSION: &'static str = "spctx";
    const VERSION: (u16, u16) = SPARK_CONTEXT_VERSION;
    const COMPRESSION: Compression = Compression::Zstd;
}

impl MaybeHashAware for SparkProverContext {
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

/// Challenges drawn from the Fiat-Shamir transcript during proving.
#[derive(Debug, Clone)]
pub struct Challenges {
    pub gamma: FieldElement,
    pub tau:   FieldElement,
}
