use {
    crate::{utils::serde_ark, FieldElement},
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Point {
    #[serde(with = "serde_ark")]
    pub row: Vec<FieldElement>,
    #[serde(with = "serde_ark")]
    pub col: Vec<FieldElement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1CSSparkQuery {
    pub point_to_evaluate:          Point,
    #[serde(with = "serde_ark")]
    pub matrix_batching_randomness: FieldElement,
    #[serde(with = "serde_ark")]
    pub claimed_value:              FieldElement,
}
