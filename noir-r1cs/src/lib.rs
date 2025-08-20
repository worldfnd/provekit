#![doc = include_str!("../README.md")]
#![allow(missing_docs)]
mod binops;
mod digits;
mod file;
mod gnark_config;
mod interner;
mod memory;
mod noir_proof_scheme;
mod noir_to_r1cs;
mod noir_witness;
mod r1cs;
mod r1cs_solver;
mod ram;
mod range_check;
mod rom;
mod skyscraper;
mod sparse_matrix;
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
    skyscraper::SkyscraperSponge,
    sparse_matrix::{HydratedSparseMatrix, SparseMatrix},
    whir::crypto::fields::Field256 as FieldElement,
    whir_r1cs::IOPattern,
};
use {
    crate::{
        interner::{InternedFieldElement, Interner},
        noir_witness::NoirWitnessGenerator,
        utils::serde_ark,
    },
    serde::{Deserialize, Serialize},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    #[serde(with = "serde_ark")]
    transcript: Vec<FieldElement>,
}
