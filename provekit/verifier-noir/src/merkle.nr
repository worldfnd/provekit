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

/// Verify a Merkle authentication path.
///
/// 1. Hash the leaf via `length_iv_hash::<LEAF_SIZE>(leaf)`.
/// 2. For each level i in 0..TREE_HEIGHT:
///    - Read bit i of `index` (lowest bit is the leaf-level pairing).
///    - If bit i == 0: parent = length_iv_hash::<2>([current, siblings[i]]).
///    - If bit i == 1: parent = length_iv_hash::<2>([siblings[i], current]).
/// 3. Assert the final parent equals `root`.
///
/// Matches WHIR's Merkle tree construction (binary, leaf-grain via
/// `poseidon2_hash_bytes` which equals `length_iv_hash` for field-aligned input).
pub fn verify_merkle_path<let LEAF_SIZE: u32, let TREE_HEIGHT: u32>(
    leaf: [Field; LEAF_SIZE],
    siblings: [Field; TREE_HEIGHT],
    index: u32,
    root: Field,
) {
    let mut current = length_iv_hash::<LEAF_SIZE>(leaf);
    let mut idx = index;
    for i in 0..TREE_HEIGHT {
        let sibling = siblings[i];
        let bit = idx & 1;
        let pair: [Field; 2] = if bit == 0 {
            [current, sibling]
        } else {
            [sibling, current]
        };
        current = length_iv_hash::<2>(pair);
        idx >>= 1;
    }
    assert(current == root);
}

// --- in-circuit KAT ---
//
// EXPECTED_HASH_2 freezes length_iv_hash([1, 2]) per the Rust
// `poseidon2::poseidon2_hash` reference.
// See provekit/verifier-noir-test/tests/merkle_kat.rs for the cross-impl guarantee.
//
// Value computed by Rust `poseidon2::poseidon2_hash` on `[1, 2]`;
// frozen as a KAT. See provekit/verifier-noir-test/tests/merkle_kat.rs
// for the cross-impl guarantee.
global EXPECTED_HASH_2: Field = 1594597865669602199208529098208508950092942746041644072252494753744672355203;

#[test]
fn length_iv_hash_2_matches_frozen_kat() {
    let out = length_iv_hash::<2>([1, 2]);
    assert(out == EXPECTED_HASH_2);
}

// --- in-circuit Merkle path KAT (placeholder) ---
//
// 4-leaf tree (TREE_HEIGHT = 2), leaves = [Field; 1] each.
//
//   leaves: [L0, L1, L2, L3] = [[1], [2], [3], [4]]
//   leaf hashes via length_iv_hash::<1>; pair hashes via length_iv_hash::<2>.
//   root = h(h(L0_h, L1_h), h(L2_h, L3_h))
//
// We verify path to leaf index 1 (= L1 = [2]):
//   siblings[0] = length_iv_hash([1])             (sibling at leaf level)
//   siblings[1] = h(length_iv_hash([3]), length_iv_hash([4]))  (sibling at level 1)
//
// EXPECTED_PATH_ROOT and EXPECTED_PATH_SIBLINGS are frozen here. Task 2 unfreezes them.
//
// PLACEHOLDER VALUES - overwritten in Phase 3A Task 2.
global EXPECTED_PATH_ROOT: Field = 0;
global EXPECTED_PATH_SIBLINGS: [Field; 2] = [0, 0];

#[test]
fn verify_merkle_path_matches_frozen_kat() {
    let leaf: [Field; 1] = [2];
    let index: u32 = 1;
    verify_merkle_path::<1, 2>(leaf, EXPECTED_PATH_SIBLINGS, index, EXPECTED_PATH_ROOT);
}
