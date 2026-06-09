pub(crate) mod gpa;
pub(crate) mod memory;
pub(crate) mod prover;
mod serde_whir_witness;
pub(crate) mod setup;
pub(crate) mod sumcheck;
pub(crate) mod types;
pub(crate) mod utils;
pub(crate) mod verifier;

pub use {
    provekit_common::{MatrixDimensions, SparkSetup, SparkWhirConfigs},
    prover::SparkProverScheme,
    setup::preprocess_spark,
    types::{SparkMatrix, SparkProof, SparkProverContext, SparkWitnesses},
    utils::calculate_memory,
    verifier::SparkVerifierScheme,
};
