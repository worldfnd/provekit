use {
    crate::{utils::serde_ark, FieldElement},
    anyhow::{Context, Result},
    serde::{Deserialize, Serialize},
    sha3::{Digest, Sha3_256},
};

/// A single column-axis SPARK query: an evaluation point on the column axis
/// plus three claimed evaluations (for the A, B, C matrices). The row axis is
/// shared across all queries in a [`SparkQueryBatch`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkColQuery {
    #[serde(with = "serde_ark")]
    pub col:       Vec<FieldElement>,
    #[serde(with = "serde_ark")]
    pub claimed_a: FieldElement,
    #[serde(with = "serde_ark")]
    pub claimed_b: FieldElement,
    #[serde(with = "serde_ark")]
    pub claimed_c: FieldElement,
}

/// A batch of SPARK queries that all share the same row evaluation point.
/// The shared-row invariant is structural: a batch *cannot* express a
/// mixed-row set, so the SPARK prover and verifier do not need a runtime
/// check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkQueryBatch {
    #[serde(with = "serde_ark")]
    pub row:     Vec<FieldElement>,
    pub queries: Vec<SparkColQuery>,
}

impl SparkQueryBatch {
    /// Stable Fiat-Shamir instance binding for the batch.
    pub fn hash_bytes(&self) -> Result<[u8; 32]> {
        let bytes =
            postcard::to_allocvec(self).context("serializing SparkQueryBatch for hash_bytes")?;
        Ok(Sha3_256::digest(&bytes).into())
    }
}
