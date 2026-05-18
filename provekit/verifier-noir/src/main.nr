// ProveKit Noir Recursive Verifier
//
// Verifies a ProveKit WHIR+Spartan proof generated under HashConfig::Poseidon2.
// See docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md
//
// Phase 2A: + Poseidon2 length-IV hash + Spartan sumcheck. Matrix eval + WHIR land later.

mod poseidon2;
mod sponge;
mod transcript;
mod merkle;
mod sumcheck;

fn main() {}
