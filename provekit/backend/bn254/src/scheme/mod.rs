//! Serialized on-disk scheme types: the ProveKit Prover (`.pkp`), Verifier
//! (`.pkv`), and proof scheme (`.nps`) structures, plus their file-format glue.

#[cfg(not(target_arch = "wasm32"))]
mod file_format;
mod mavros;
mod proof_scheme;
mod prover;
mod verifier;

pub use {
    mavros::{MavrosProver, MavrosSchemeData},
    proof_scheme::{NoirProofScheme, NoirSchemeData},
    prover::{NoirProver, Prover},
    verifier::Verifier,
};
