#![doc = include_str!("../README.md")]
#![allow(missing_docs)]
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
    crate::{noir_witness::NoirWitnessGenerator, utils::serde_ark, whir_r1cs::WhirProof},
    serde::{Deserialize, Serialize},
    sparse_matrix::SparseMatrix,
};
pub use {
    acir::FieldElement as NoirElement, noir_proof_scheme::NoirProofScheme,
    noir_to_r1cs::noir_to_r1cs, r1cs::R1CS, whir::crypto::fields::Field256 as FieldElement,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    #[serde(with = "serde_ark")]
    transcript: Vec<FieldElement>,
    #[serde(with = "serde_ark")]
    whir_proof: WhirProof,
}

#[cfg(test)]
#[track_caller]
fn test_serde<T: std::fmt::Debug + PartialEq + Serialize + for<'a> Deserialize<'a>>(value: &T) {
    // Test JSON
    let json = serde_json::to_string(value).unwrap();
    let deserialized = serde_json::from_str(&json).unwrap();
    assert_eq!(value, &deserialized);

    // Test Postcard
    let bin = postcard::to_allocvec(value).unwrap();
    let deserialized = postcard::from_bytes(&bin).unwrap();
    assert_eq!(value, &deserialized);
}
