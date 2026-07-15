use {
    crate::{Bn254Field, FieldElement, WhirConfig},
    anyhow::{Context, Result},
    provekit_common::{utils::serde_ark, HashConfig, WhirR1CSProof},
    provekit_prover::{SparkColQueryData, SparkQueryData},
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

// For bn254 the base and extension fields coincide (`Identity<Fr>`), so the
// generic query data from `provekit-prover` maps directly onto the serialized
// batch type.
impl From<SparkQueryData<Bn254Field>> for SparkQueryBatch {
    fn from(data: SparkQueryData<Bn254Field>) -> Self {
        Self {
            row:     data.row,
            queries: data.queries.into_iter().map(SparkColQuery::from).collect(),
        }
    }
}

impl From<SparkColQueryData<Bn254Field>> for SparkColQuery {
    fn from(query: SparkColQueryData<Bn254Field>) -> Self {
        Self {
            col:       query.col,
            claimed_a: query.claimed_a,
            claimed_b: query.claimed_b,
            claimed_c: query.claimed_c,
        }
    }
}

/// Dimensions of the (padded) sparse R1CS matrix that SPARK is committing to.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MatrixDimensions {
    pub num_rows:      usize,
    pub num_cols:      usize,
    pub nonzero_terms: usize,
}

/// WHIR configurations used by SPARK for each committed polynomial axis.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SparkWhirConfigs {
    pub row:                WhirConfig,
    pub col:                WhirConfig,
    pub num_terms_2batched: WhirConfig,
    pub num_terms_5batched: WhirConfig,
}

/// Verifier-side SPARK setup: WHIR configs, matrix dimensions, the preprocessed
/// commitment transcript, and the hash config used to seed Fiat-Shamir.
///
/// This struct is embedded in [`Verifier`](crate::Verifier) so the SPARK
/// commitments come from the trusted `.pkv` key rather than an attacker-
/// supplied setup file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparkSetup {
    pub whir_configs:      SparkWhirConfigs,
    pub matrix_dimensions: MatrixDimensions,
    pub transcript:        WhirR1CSProof,
    pub hash_config:       HashConfig,
}
