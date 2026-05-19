// ProveKit Noir Recursive Verifier
//
// Verifies a ProveKit WHIR+Spartan proof generated under HashConfig::Poseidon2.
// See docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md
//
// Phase 2C: + codegen-emitted `types` module. Full integration lands in Phase 3.

mod poseidon2;
mod sponge;
mod transcript;
mod merkle;
mod sumcheck;
mod matrix_eval;
mod public_input;

mod types;
mod matrices;
mod whir;

fn main() {}
