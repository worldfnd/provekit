pub mod gpa;
pub mod iopattern;
pub mod matrix;
pub mod memory;
pub mod spark;
pub mod whir;

use {
    crate::utilities::whir::SPARKWHIRConfigsNew,
    anyhow::{Context, Result},
    provekit_common::{
        gnark::WHIRConfigGnark, spark::SPARKRequest, utils::next_power_of_two, R1CS,
    },
    serde::{Deserialize, Serialize},
    std::{fs, path::PathBuf},
};

pub fn deserialize_r1cs(path: &PathBuf) -> Result<R1CS> {
    let json_str =
        fs::read_to_string(path).context("Error: Failed to open the r1cs.json file")?;
    let mut r1cs: R1CS =
        serde_json::from_str(&json_str).context("Error: Failed to deserialize JSON to R1CS")?;
    r1cs.grow_matrices(
        1 << next_power_of_two(r1cs.num_constraints()),
        1 << next_power_of_two(r1cs.num_witnesses()),
    );
    Ok(r1cs)
}

pub fn deserialize_request(path: &PathBuf) -> Result<SPARKRequest> {
    let json_str =
        fs::read_to_string(path).context("Error: Failed to open the request.json file")?;
    serde_json::from_str(&json_str).context("Error: Failed to deserialize JSON to R1CS")
}

#[derive(Serialize, Deserialize)]
pub struct SPARKProof {
    pub transcript:        Vec<u8>,
    pub io_pattern:        String,
    pub whir_params:       SPARKWHIRConfigsNew,
    pub matrix_dimensions: MatrixDimensionsNew,
}

#[derive(Serialize, Deserialize)]
pub struct MatrixDimensions {
    pub num_rows:        usize,
    pub num_cols:        usize,
    pub a_nonzero_terms: usize,
    pub b_nonzero_terms: usize,
    pub c_nonzero_terms: usize,
}

#[derive(Serialize, Deserialize)]
pub struct MatrixDimensionsNew {
    pub num_rows:      usize,
    pub num_cols:      usize,
    pub nonzero_terms: usize,
}

pub fn calculate_matrix_dimensions(r1cs: &R1CS) -> MatrixDimensions {
    MatrixDimensions {
        num_rows:        r1cs.a.num_rows,
        num_cols:        r1cs.a.num_cols,
        a_nonzero_terms: r1cs.a.num_entries(),
        b_nonzero_terms: r1cs.b.num_entries(),
        c_nonzero_terms: r1cs.c.num_entries(),
    }
}

#[derive(Serialize, Deserialize)]
pub struct SPARKProofGnark {
    pub transcript:      Vec<u8>,
    pub io_pattern:      String,
    pub whir_row:        WHIRConfigGnark,
    pub whir_col:        WHIRConfigGnark,
    pub whir_a3:         WHIRConfigGnark,
    pub whir_b3:         WHIRConfigGnark,
    pub whir_c3:         WHIRConfigGnark,
    pub log_a_num_terms: usize,
    pub log_b_num_terms: usize,
    pub log_c_num_terms: usize,
}

#[derive(Serialize, Deserialize)]
pub struct SPARKProofGnarkNew {
    pub transcript:    Vec<u8>,
    pub io_pattern:    String,
    pub whir_row:      WHIRConfigGnark,
    pub whir_col:      WHIRConfigGnark,
    pub whir_3batched: WHIRConfigGnark,
    pub whir_5batched: WHIRConfigGnark,
    pub log_num_terms: usize,
}
