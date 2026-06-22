pub mod bigint_mod;
mod compress;
pub mod ec_arith;
pub mod file;
pub use file::binary_format;
pub mod field;
pub mod hash_config;
mod interner;
mod logging;
pub mod prefix_covector;
pub mod public_inputs;
mod r1cs;
pub mod sparse_matrix;
pub mod u256_arith;
pub mod utils;
mod whir_r1cs;

// The R1CS matrix interner is part of the matrix-construction internals, not a
// stable public type; exposed only so the Noir compiler (a separate crate) can
// build and optimize matrices.
#[doc(hidden)]
pub use crate::interner::{InternedFieldElement, Interner};
pub use {
    // TODO(P0.4): bn254-only alias and the migration lynchpin. Deleting it (once
    // provekit-backend-bn254 owns `Fr`) is the final P0.4 step; it forces removal
    // of every `= FieldElement` / `= Bn254Field` default type param across the
    // spine. The compiler flags each site, so those defaults need no individual
    // markers.
    ark_bn254::Fr as FieldElement,
    compress::CompressedR1CS,
    field::{Base, Ext, FieldHash, ProofField},
    hash_config::{HashConfig, POSEIDON2, SKYSCRAPER},
    logging::log_commit_input,
    prefix_covector::{OffsetCovector, PrefixCovector, SparseCovector},
    public_inputs::{PublicInputs, PublicInputsHash},
    r1cs::R1CS,
    sparse_matrix::{HydratedSparseMatrix, SparseMatrix},
    whir_r1cs::{ProvekitProof, R1csHash, WhirR1CSProof, WhirR1CSScheme},
};
