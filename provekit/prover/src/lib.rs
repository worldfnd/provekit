//! Generic WHIR proving engine for ProveKit.
//!
//! Field- and frontend-agnostic: it operates on an `R1CS` instance, a solved
//! witness vector, and a `WhirR1CSScheme` (all from `provekit-common`), and
//! produces a `WhirR1CSProof`. It names no concrete field and no Noir/ACIR
//! types — the Noir/mavros orchestration and the witness solving live in
//! `provekit-noir`, and the field backend is registered by the caller.

pub mod whir_r1cs;

pub use whir_r1cs::{
    compute_blinding_coefficients_for_round, pad_to_pow2_len_min2, run_zk_sumcheck_prover,
    sum_over_hypercube, BlindingState, WhirR1CSCommitment, WhirR1CSProver,
};
