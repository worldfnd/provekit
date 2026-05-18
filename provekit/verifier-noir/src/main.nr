// ProveKit Noir Recursive Verifier
//
// Verifies a ProveKit WHIR+Spartan proof generated under HashConfig::Poseidon2.
// See docs/superpowers/specs/2026-05-18-noir-recursive-verifier-design.md
//
// Phase 1B: + duplex sponge + transcript. Verification logic lands in later phases.

mod poseidon2;
mod sponge;
mod transcript;

fn main() {}
