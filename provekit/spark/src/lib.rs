pub mod gpa;
pub mod memory;
pub mod prover;
mod serde_whir_witness;
pub mod setup;
pub mod sumcheck;
pub mod types;
pub mod utils;
pub mod verifier;

pub use {
    prover::{SparkProver, SparkScheme as SparkProverScheme},
    setup::preprocess_spark,
    types::{
        MatrixDimensions, SparkProof, SparkSetup, SparkWhirConfigs, SparkProverContext,
        SparkWitnesses,
    },
    utils::calculate_memory,
    verifier::{SparkScheme as SparkVerifierScheme, SparkVerifier},
};
