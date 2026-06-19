//! BN254 backend for the ProveKit proof-system spine.
//!
//! ProveKit's `common`/`prover`/`verifier` crates are generic over a
//! [`provekit_common::ProofField`]. This crate provides the BN254
//! instantiation — the degenerate `Identity<Fr>` case where the base
//! (committed) field and the extension (challenge) field coincide with the
//! BN254 scalar field. A binary "picks BN254" by depending on this crate.
