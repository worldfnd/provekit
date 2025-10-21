pub mod file;
mod interner;
mod noir_proof_scheme;
pub mod ntt;
mod prover;
mod r1cs;
pub mod skyscraper;
mod sparse_matrix;
pub mod utils;
mod verifier;
mod whir_r1cs;
pub mod witness;

use crate::{
    interner::{InternedFieldElement, Interner},
    sparse_matrix::{HydratedSparseMatrix, SparseMatrix},
};
pub use {
    acir::FieldElement as NoirElement,
    ark_bn254::Fr as FieldElement,
    noir_proof_scheme::{NoirProof, NoirProofScheme},
    prover::Prover,
    r1cs::R1CS,
    verifier::Verifier,
    whir_r1cs::{IOPattern, WhirConfig, WhirR1CSProof, WhirR1CSScheme},
};

#[cfg(test)]
mod tests {}
