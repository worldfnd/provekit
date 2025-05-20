#![doc = include_str!("../README.md")]
#![allow(missing_docs)]
mod file;
mod gnark_config;
mod interner;
mod noir_proof_scheme;
mod noir_to_r1cs;
mod noir_witness;
mod r1cs;
mod r1cs_solver;
mod skyscraper;
mod sparse_matrix;
mod test_functions;
pub mod utils;
mod whir_r1cs;

pub use {
    crate::{
        file::{read, write, FileFormat},
        noir_proof_scheme::{NoirProof, NoirProofScheme},
        noir_to_r1cs::noir_to_r1cs,
        r1cs::R1CS,
        utils::human,
    },
    acir::FieldElement as NoirElement,
    gnark_config::write_gnark_parameters_to_file,
    whir::crypto::fields::Field256 as FieldElement,
    whir_r1cs::create_io_pattern,
};
use {
    crate::{
        interner::{InternedFieldElement, Interner},
        noir_witness::NoirWitnessGenerator,
        sparse_matrix::{HydratedSparseMatrix, SparseMatrix},
        utils::serde_ark,
        whir_r1cs::WhirProof,
    },
    serde::{Deserialize, Serialize},
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
