//! Poseidon2 length-IV one-shot hash used by WHIR's Merkle tree.
//!
//! Distinct from the duplex sponge in `sponge.nr`:
//!   * state[3] is initialized to `N * 2^64` (length-domain-separation IV)
//!   * inputs are ADDED (not overwritten) into rate lanes
//!   * a final permute fires after the last absorbed input
//!
//! Mirrors `poseidon2::hash::poseidon2_hash` from the workspace `poseidon2`
//! crate, which itself matches Noir stdlib's `Poseidon2::hash(inputs, len)`.
//!
//! Cross-implementation KAT lives in
//! `provekit/verifier-noir-test/tests/merkle_kat.rs`.

use crate::poseidon2::permute;

global HASH_RATE: u32 = 3;

/// `2^64` as a Field constant. Used as a multiplier on the message length to
/// derive the capacity-lane IV.
global TWO_POW_64: Field = 0x10000000000000000;

/// One-shot Poseidon2 hash with length-domain-separation in the capacity lane.
///
/// `IV = N * 2^64` is placed in `state[3]`. Inputs are absorbed in chunks of
/// `HASH_RATE = 3`, ADDED into the rate lanes (state[0..3]). Permute fires
/// when the chunk fills RATE; the final partial chunk is ADDed and a final
/// permute runs unconditionally. Output is `state[0]`.
pub fn length_iv_hash<let N: u32>(inputs: [Field; N]) -> Field {
    let iv = (N as Field) * TWO_POW_64;
    let mut state: [Field; 4] = [0, 0, 0, iv];
    let mut cache: [Field; 3] = [0, 0, 0];
    let mut cache_size: u32 = 0;

    for i in 0..N {
        if cache_size == HASH_RATE {
            // Cache full: ADD into state, permute, clear cache.
            state[0] += cache[0];
            state[1] += cache[1];
            state[2] += cache[2];
            cache = [0, 0, 0];
            cache_size = 0;
            state = permute(state);
        }
        cache[cache_size] = inputs[i];
        cache_size += 1;
    }

    // Final: ADD remaining cache lanes into state, permute, output state[0].
    // Unrolled to honor `cache_size`'s remaining value without per-lane branches.
    if cache_size > 0 {
        state[0] += cache[0];
    }
    if cache_size > 1 {
        state[1] += cache[1];
    }
    if cache_size > 2 {
        state[2] += cache[2];
    }
    state = permute(state);
    state[0]
}

// --- in-circuit KAT ---
//
// EXPECTED_HASH_2 freezes length_iv_hash([1, 2]) per the Rust
// `poseidon2::hash::poseidon2_hash` reference. Task 2 replaces this
// placeholder with the real value.
//
// PLACEHOLDER VALUE - overwritten in Phase 2A Task 2 after running the
// Rust-side computation. The test below is expected to FAIL until then.
global EXPECTED_HASH_2: Field = 0;

#[test]
fn length_iv_hash_2_matches_frozen_kat() {
    let out = length_iv_hash::<2>([1, 2]);
    assert(out == EXPECTED_HASH_2);
}
