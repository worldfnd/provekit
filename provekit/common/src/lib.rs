pub mod file;
mod interner;
mod noir_proof_scheme;
mod prover;
mod r1cs;
pub mod skyscraper;
mod sparse_matrix;
pub mod utils;
mod verifier;
mod whir_r1cs;
pub mod witness;

use crate::sparse_matrix::{HydratedSparseMatrix, SparseMatrix};
pub use {
    acir::FieldElement as NoirElement,
    interner::{InternedFieldElement, Interner},
    noir_proof_scheme::{NoirProof, NoirProofScheme},
    prover::Prover,
    r1cs::R1CS,
    verifier::Verifier,
    spartan_vm::compiler::Field as FieldElement,
    whir_r1cs::{IOPattern, WhirConfig, WhirR1CSProof, WhirR1CSScheme},
};

#[cfg(test)]
mod tests {}
