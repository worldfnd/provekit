pub mod gpa;
pub mod memory;
pub mod prover;
pub mod sumcheck;
pub mod types;
pub mod utils;
pub mod verifier;

pub use {
    prover::{SPARKProver, SPARKScheme as SPARKProverScheme},
    types::{MatrixDimensions, SPARKProof, SPARKProofGnark, SPARKWHIRConfigs},
    utils::{calculate_memory, deserialize_r1cs, deserialize_request},
    verifier::{SPARKScheme as SPARKVerifierScheme, SPARKVerifier},
};
