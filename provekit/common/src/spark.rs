use {
    crate::{utils::serde_ark, FieldElement},
    serde::{Deserialize, Serialize},
    sha3::{Digest, Sha3_256},
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
    pub point_to_evaluate: Point,
    #[serde(with = "serde_ark")]
    pub claimed_a:         FieldElement,
    #[serde(with = "serde_ark")]
    pub claimed_b:         FieldElement,
    #[serde(with = "serde_ark")]
    pub claimed_c:         FieldElement,
}

impl R1CSSparkQuery {
    pub fn hash_bytes(&self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(self).expect("serializing R1CSSparkQuery");
        Sha3_256::digest(&bytes).into()
    }
}
