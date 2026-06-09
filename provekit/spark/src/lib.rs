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
    prover::SparkProverScheme,
    setup::preprocess_spark,
    types::{
        MatrixDimensions, SparkMatrix, SparkProof, SparkProverContext, SparkSetup,
        SparkWhirConfigs, SparkWitnesses,
    },
    utils::calculate_memory,
    verifier::SparkVerifierScheme,
};
