mod iopattern;
pub mod matrix;
use {
    crate::whir::SPARKWHIRConfigs,
    anyhow::{Context, Result},
    provekit_common::{
        spark::SPARKRequest, utils::{next_power_of_two, serde_ark, sumcheck::calculate_evaluations_over_boolean_hypercube_for_eq}, FieldElement, HydratedSparseMatrix, WhirConfig, R1CS
    },
    serde::{Deserialize, Serialize},
    std::fs,
};
pub use {iopattern::create_io_pattern, matrix::get_spark_r1cs};

pub fn deserialize_r1cs(path_str: &str) -> Result<R1CS> {
    let json_str =
        fs::read_to_string(path_str).context("Error: Failed to open the r1cs.json file")?;
    let mut r1cs: R1CS = serde_json::from_str(&json_str).context("Error: Failed to deserialize JSON to R1CS")?;
    r1cs.grow_matrices(
        1<<next_power_of_two(r1cs.num_constraints()), 
        1 << next_power_of_two(r1cs.num_witnesses()),
    );
    Ok(r1cs)
}

pub fn deserialize_request(path_str: &str) -> Result<SPARKRequest> {
    let json_str =
        fs::read_to_string(path_str).context("Error: Failed to open the request.json file")?;
    serde_json::from_str(&json_str).context("Error: Failed to deserialize JSON to R1CS")
}

#[derive(Serialize, Deserialize)]
pub struct SPARKProof {
    pub transcript:        Vec<u8>,
    pub io_pattern:        String,
    pub whir_params:       SPARKWHIRConfigs,
    pub matrix_dimensions: MatrixDimensions,
}

#[derive(Serialize, Deserialize)]
pub struct MatrixDimensions {
    pub num_rows:        usize,
    pub num_cols:        usize,
    pub a_nonzero_terms: usize,
    pub b_nonzero_terms: usize,
    pub c_nonzero_terms: usize,
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
