pub mod file;
pub mod gnark;
mod interner;
mod noir_proof_scheme;
mod r1cs;
pub mod skyscraper;
pub mod spark;
mod sparse_matrix;
pub mod utils;
mod whir_r1cs;
pub mod witness;

use crate::interner::{InternedFieldElement, Interner};
pub use {
    acir::FieldElement as NoirElement,
    noir_proof_scheme::{NoirProof, NoirProofScheme},
    r1cs::R1CS,
    sparse_matrix::{HydratedSparseMatrix, SparseMatrix},
    whir::crypto::fields::Field256 as FieldElement,
    whir_r1cs::{IOPattern, WhirConfig, WhirR1CSProof, WhirR1CSScheme},
};

#[cfg(test)]
mod tests {}
