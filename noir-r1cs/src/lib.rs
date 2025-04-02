#![allow(missing_docs)]
mod ark_serde;
mod noir_proof_scheme;
pub mod noir_to_r1cs;
pub mod noir_witness;
pub mod prover;
pub mod r1cs;
pub mod sparse_matrix;
pub mod utils;
pub mod whir_r1cs;

use {
    crate::{noir_witness::NoirWitnessGenerator, whir_r1cs::WhirProof},
    serde::{Deserialize, Serialize},
    sparse_matrix::SparseMatrix,
};
pub use {
    acir::FieldElement as NoirElement, noir_proof_scheme::NoirProofScheme,
    noir_to_r1cs::noir_to_r1cs, r1cs::R1CS, whir::crypto::fields::Field256 as FieldElement,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    #[serde(with = "crate::ark_serde")]
    transcript: Vec<FieldElement>,
    #[serde(with = "crate::ark_serde")]
    whir_proof: WhirProof,
}
