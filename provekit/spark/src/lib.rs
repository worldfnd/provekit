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
    prover::{SPARKProver, SPARKScheme as SPARKProverScheme},
    setup::preprocess_spark,
    types::{
        MatrixDimensions, SPARKProof, SPARKSetup, SPARKWHIRConfigs, SparkProverContext,
        SparkWitnesses,
    },
    utils::calculate_memory,
    verifier::{SPARKScheme as SPARKVerifierScheme, SPARKVerifier},
};
