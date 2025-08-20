mod iopattern;
mod matrix;
use {
    anyhow::{Context, Result},
    noir_r1cs::{
        utils::{serde_ark, sumcheck::calculate_evaluations_over_boolean_hypercube_for_eq},
        FieldElement, R1CS,
    },
    serde::{Deserialize, Serialize},
    std::fs,
};
pub use {iopattern::create_io_pattern, matrix::get_spark_r1cs};

pub fn deserialize_r1cs(path_str: &str) -> Result<R1CS> {
    let json_str =
        fs::read_to_string(path_str).context("Error: Failed to open the r1cs.json file")?;
    serde_json::from_str(&json_str).context("Error: Failed to deserialize JSON to R1CS")
}

pub fn deserialize_request(path_str: &str) -> Result<SPARKRequest> {
    let json_str =
        fs::read_to_string(path_str).context("Error: Failed to open the request.json file")?;
    serde_json::from_str(&json_str).context("Error: Failed to deserialize JSON to R1CS")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SPARKRequest {
    pub point_to_evaluate: Point,
    pub claimed_values:    ClaimedValues,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Point {
    #[serde(with = "serde_ark")]
    pub row: Vec<FieldElement>,
    #[serde(with = "serde_ark")]
    pub col: Vec<FieldElement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimedValues {
    #[serde(with = "serde_ark")]
    pub a: FieldElement,
    #[serde(with = "serde_ark")]
    pub b: FieldElement,
    #[serde(with = "serde_ark")]
    pub c: FieldElement,
}

#[derive(Debug)]
pub struct Memory {
    eq_rx: Vec<FieldElement>,
    eq_ry: Vec<FieldElement>,
}

pub fn calculate_memory(point_to_evaluate: Point) -> Memory {
    Memory {
        eq_rx: calculate_evaluations_over_boolean_hypercube_for_eq(&point_to_evaluate.row),
        eq_ry: calculate_evaluations_over_boolean_hypercube_for_eq(&point_to_evaluate.col),
    }
}
