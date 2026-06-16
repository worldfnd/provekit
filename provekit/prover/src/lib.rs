//! Generic WHIR proving engine for ProveKit.
//!
//! Operates on an `R1CS`, a solved witness, and a `WhirR1CSScheme` (all from
//! `provekit-common`) and produces a `WhirR1CSProof`. Names no field or
//! Noir/ACIR types; the orchestration and witness solving live in
//! `provekit-noir`.

pub mod whir_r1cs;

pub use whir_r1cs::{
    compute_blinding_coefficients_for_round, pad_to_pow2_len_min2, run_zk_sumcheck_prover,
    sum_over_hypercube, BlindingState, WhirR1CSCommitment, WhirR1CSProver,
};
