pub mod gpa;
pub mod memory;
pub mod preprocessing;
pub mod prover;
pub mod sumcheck;
pub mod types;
pub mod utils;
pub mod verifier;

pub use {
    prover::{SPARKProver, SPARKScheme as SPARKProverScheme},
    types::{
        ClaimedValues, MatrixDimensions, Point, SPARKProof, SPARKProofGnark, SPARKRequest,
        SPARKWHIRConfigs,
    },
    utils::{calculate_memory, deserialize_r1cs, deserialize_request},
    verifier::{SPARKScheme as SPARKVerifierScheme, SPARKVerifier},
};
