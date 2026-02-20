pub mod constants;
mod hash;
pub mod permutation;

pub use {
    hash::poseidon2_hash,
    permutation::{poseidon2_permutation, Poseidon2, Poseidon2Config, POSEIDON2_CONFIG},
};
