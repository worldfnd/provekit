//! Thin wrapper over Noir's stdlib BN254 Poseidon2 permutation.
//!
//! The state shape and permutation parameters match the Rust `poseidon2`
//! workspace crate at the same input - see the cross-implementation KAT in
//! `provekit/verifier-noir-test/tests/poseidon2_kat.rs` for the bit-for-bit
//! guarantee.

use std::hash::poseidon2_permutation;

/// Apply one round of the BN254 Poseidon2 permutation to a 4-lane state.
pub fn permute(state: [Field; 4]) -> [Field; 4] {
    poseidon2_permutation(state, 4)
}

// --- in-circuit KAT ---
//
// EXPECTED_PERMUTE_1234 is the output of Poseidon2 on [1, 2, 3, 4]. It is
// computed once by the Rust `poseidon2` crate (see Task 4) and frozen here.
// If Noir's stdlib permutation ever drifts from the Rust crate, this test
// fails - and the cross-impl KAT in `verifier-noir-test` fails alongside it.
//
// PLACEHOLDER VALUE - overwritten in Task 4 step 3 after running the
// Rust-side computation. The test below is expected to FAIL until then.
global EXPECTED_PERMUTE_1234: [Field; 4] = [0, 0, 0, 0];

#[test]
fn permutation_1234_matches_frozen_kat() {
    let input: [Field; 4] = [1, 2, 3, 4];
    let output = permute(input);
    assert(output == EXPECTED_PERMUTE_1234);
}
