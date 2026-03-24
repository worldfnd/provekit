pub mod gpa;
pub mod memory;
pub mod prover;
pub mod sumcheck;
pub mod types;
pub mod utils;
pub mod verifier;

pub use {
    prover::{SPARKProver, SPARKScheme as SPARKProverScheme},
    types::{MatrixDimensions, SPARKProof, SPARKWHIRConfigs, SerializableSparkWitnesses, SparkCommitments, SparkPreparedData, SparkWitnesses},
    utils::calculate_memory,
    verifier::{SPARKScheme as SPARKVerifierScheme, SPARKVerifier},
};
