use {
    provekit_common::{FieldElement, WhirConfig},
    serde::{Deserialize, Serialize},
};

/// Complete SPARK proof including transcript and configuration.
#[derive(Serialize, Deserialize)]
pub struct SPARKProof {
    pub transcript:        Vec<u8>,
    pub io_pattern:        String,
    pub whir_params:       SPARKWHIRConfigs,
    pub matrix_dimensions: MatrixDimensions,
}

/// Dimensions of the R1CS matrices used in the proof.
#[derive(Serialize, Deserialize, Clone)]
pub struct MatrixDimensions {
    pub num_rows:      usize,
    pub num_cols:      usize,
    pub nonzero_terms: usize,
}

/// WHIR commitment scheme configurations for different vector sizes.
#[derive(Serialize, Deserialize, Clone)]
pub struct SPARKWHIRConfigs {
    pub row:                WhirConfig,
    pub col:                WhirConfig,
    pub num_terms_2batched: WhirConfig,
    pub num_terms_3batched: WhirConfig,
    pub num_terms_4batched: WhirConfig,
}

/// SPARK matrix in COO format with memory access timestamps.
#[derive(Debug, Clone)]
pub struct SparkMatrix {
    pub coo:        COOMatrix,
    pub timestamps: TimeStamps,
}

/// Coordinate (COO) sparse matrix format storing row/col indices and values.
#[derive(Debug, Clone)]
pub struct COOMatrix {
    pub row:   Vec<FieldElement>,
    pub col:   Vec<FieldElement>,
    pub val:   Vec<FieldElement>,
    pub val_a: Vec<FieldElement>,
    pub val_b: Vec<FieldElement>,
    pub val_c: Vec<FieldElement>,
}

/// Memory access timestamps for GPA protocol.
#[derive(Debug, Clone)]
pub struct TimeStamps {
    pub read_row:  Vec<FieldElement>,
    pub read_col:  Vec<FieldElement>,
    pub final_row: Vec<FieldElement>,
    pub final_col: Vec<FieldElement>,
}

/// Precomputed equality check evaluations for memory arguments.
#[derive(Debug, Clone)]
pub struct Memory {
    pub eq_rx: Vec<FieldElement>,
    pub eq_ry: Vec<FieldElement>,
}

/// Row and column evaluation vectors at the challenge point.
#[derive(Debug, Clone)]
pub struct EValuesForMatrix {
    pub e_rx: Vec<FieldElement>,
    pub e_ry: Vec<FieldElement>,
}

use provekit_common::gnark::WHIRConfigGnark;

/// SPARK proof formatted for Gnark recursive verifier.
#[derive(Serialize, Deserialize)]
pub struct SPARKProofGnark {
    pub transcript:    Vec<u8>,
    pub io_pattern:    String,
    pub whir_row:      WHIRConfigGnark,
    pub whir_col:      WHIRConfigGnark,
    pub whir_2batched: WHIRConfigGnark,
    pub whir_3batched: WHIRConfigGnark,
    pub whir_4batched: WHIRConfigGnark,
    pub log_num_terms: usize,
}

impl SPARKProofGnark {
    /// Converts SPARK proof to Gnark-compatible format.
    pub fn from_proof(proof: &SPARKProof, log_num_terms: usize) -> Self {
        Self {
            transcript: proof.transcript.clone(),
            io_pattern: proof.io_pattern.clone(),
            whir_row: WHIRConfigGnark::new(&proof.whir_params.row),
            whir_col: WHIRConfigGnark::new(&proof.whir_params.col),
            whir_2batched: WHIRConfigGnark::new(&proof.whir_params.num_terms_2batched),
            whir_3batched: WHIRConfigGnark::new(&proof.whir_params.num_terms_3batched),
            whir_4batched: WHIRConfigGnark::new(&proof.whir_params.num_terms_4batched),
            log_num_terms,
        }
    }
}
