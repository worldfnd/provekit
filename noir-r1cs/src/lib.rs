#![doc = include_str!("../README.md")]
#![allow(missing_docs)]
mod ark_serde;
mod gnark_config;
mod noir_proof_scheme;
mod noir_to_r1cs;
mod noir_witness;
mod r1cs;
mod skyscraper;
mod sparse_matrix;
mod utils;
mod whir_r1cs;

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
