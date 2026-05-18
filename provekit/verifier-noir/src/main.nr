// ProveKit Noir Recursive Verifier
//
// Verifies a ProveKit WHIR+Spartan proof generated under HashConfig::Poseidon2.
// See docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md
//
// Phase 2B: + matrix evaluation. Public-input binding lands in the next task.

mod poseidon2;
mod sponge;
mod transcript;
mod merkle;
mod sumcheck;
mod matrix_eval;

fn main() {}
