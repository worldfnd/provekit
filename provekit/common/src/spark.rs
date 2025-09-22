use serde::{Deserialize, Serialize};
use crate::FieldElement;
use crate::utils::serde_ark;


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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SPARKRequest {
    pub point_to_evaluate: Point,
    pub claimed_values:    ClaimedValues,
}
