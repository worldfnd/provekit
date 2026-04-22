// Poseidon2 Merkle Tree Verification
//
// Verifies Merkle inclusion proofs for WHIR commitment queries using the
// Poseidon2 length-IV sponge hash, matching
// `provekit/common/src/poseidon2/whir.rs::Poseidon2HashEngine::hash_message`:
//
//   state = [0, 0, 0, num_fes * 2^64]
//   for each RATE=3 chunk of inputs: state[0..3] += chunk; permute
//   (always a final permute, even for the last partial chunk)
//   return state[0]
//
// Leaf hashing:  sponge hash of all leaf field elements with IV = n_fields * 2^64.
// Node hashing:  2-to-1 compression = sponge hash of [left, right] with IV = 2 * 2^64.
// Path walk:     binary tree, index bit selects left/right child position.

use std::hash::poseidon2_permutation;

/// `2^64` as a BN254 field element; capacity-lane IV multiplier matching
/// `provekit/common/src/poseidon2/whir.rs`.
global TWO_POW_64: Field = 18446744073709551616;

/// Length-IV Poseidon2 sponge hash over `n` field elements.
///
/// Variable-size variant. Use `poseidon2_sponge_hash_fixed` for call sites
/// that absorb exactly the full typed width - it is substantially cheaper
/// because the `n` guard and `pos` dispatch both resolve at compile time.
///
/// Mirrors `Poseidon2HashEngine::hash_message` and `poseidon2::poseidon2_hash`:
/// - `state[3] = n * 2^64` (prevents zero-padding collisions)
/// - rate lanes `state[0..3]` absorb additively in batches of 3
/// - a final permute always runs after the last (possibly partial) batch
/// - output is `state[0]`
pub fn poseidon2_sponge_hash<let MAX_N: u32>(inputs: [Field; MAX_N], n: u32) -> Field {
    let iv: Field = (n as Field) * TWO_POW_64;
    let mut state: [Field; 4] = [0, 0, 0, iv];
    let mut pos: u32 = 0;

    for i in 0..MAX_N {
        if (i as u32) < n {
            if pos == 3 {
                state = poseidon2_permutation(state, 4);
                pos = 0;
            }
            if pos == 0 {
                state[0] += inputs[i];
            } else if pos == 1 {
                state[1] += inputs[i];
            } else {
                state[2] += inputs[i];
            }
            pos += 1;
        }
    }

    // Final permute always runs (matches the Rust reference).
    state = poseidon2_permutation(state, 4);
    state[0]
}

/// Length-IV Poseidon2 sponge hash over exactly N field elements.
///
/// Identical output to `poseidon2_sponge_hash(inputs, N)` but produces
/// substantially fewer ACIR opcodes by unrolling in groups of 3 with
/// compile-time lane indices - no `pos` runtime dispatch, no `i < n` guard.
///
/// Permute count: `ceil(N / 3)` (same as the variable-size variant at n=N).
pub fn poseidon2_sponge_hash_fixed<let N: u32>(inputs: [Field; N]) -> Field {
    let iv: Field = (N as Field) * TWO_POW_64;
    let mut state: [Field; 4] = [0, 0, 0, iv];
    let full_chunks: u32 = N / 3;
    let rem: u32 = N % 3;

    if full_chunks > 0 {
        // First full chunk: absorb without a preceding permute.
        state[0] += inputs[0];
        state[1] += inputs[1];
        state[2] += inputs[2];
        // Remaining full chunks each preceded by a permute.
        for chunk in 1..full_chunks {
            state = poseidon2_permutation(state, 4);
            let base = chunk * 3;
            state[0] += inputs[base];
            state[1] += inputs[base + 1];
            state[2] += inputs[base + 2];
        }
    }

    // Trailing partial chunk (N % 3 in {1, 2}), preceded by a permute if
    // any full chunks already absorbed.
    if rem != 0 {
        if full_chunks > 0 {
            state = poseidon2_permutation(state, 4);
        }
        state[0] += inputs[full_chunks * 3];
        if rem == 2 {
            state[1] += inputs[full_chunks * 3 + 1];
        }
    }

    // Final permute always runs (matches the Rust reference).
    state = poseidon2_permutation(state, 4);
    state[0]
}

/// Poseidon2 2-to-1 compression: `sponge_hash([l, r], 2)`.
///
/// Specialized form: state = [l, r, 0, 2 * 2^64], one permute, return state[0].
pub fn compress_2(l: Field, r: Field) -> Field {
    let mut state: [Field; 4] = [l, r, 0, 2 * TWO_POW_64];
    state = poseidon2_permutation(state, 4);
    state[0]
}

/// Hash a full-width leaf: absorbs exactly `LEAF_SIZE` field elements.
/// All WHIR Merkle leaves in the ProveKit scheme have `leaf_size == LEAF_SIZE`,
/// so this is the only leaf-hash helper used by `verify_merkle_proof_dynamic`.
fn hash_leaf_fixed<let LEAF_SIZE: u32>(fields: [Field; LEAF_SIZE]) -> Field {
    poseidon2_sponge_hash_fixed(fields)
}

/// Verify a single Merkle inclusion proof.
///
/// - leaf_values: the field elements at this leaf
/// - leaf_size:   number of actual field elements in the leaf
/// - siblings:    sibling hashes along the path (bottom to top)
/// - path_len:    number of levels in the path
/// - index:       leaf index in the tree (used for left/right selection)
/// - root:        expected Merkle root hash
pub fn verify_merkle_proof_dynamic<let MAX_LEAF_SIZE: u32, let MAX_HEIGHT: u32>(
    leaf_values: [Field; MAX_LEAF_SIZE],
    leaf_size: u32,
    siblings: [Field; MAX_HEIGHT],
    path_len: u32,
    index: u32,
    root: Field,
) {
    // Tightened from `<=` to `==`: in the ProveKit WHIR scheme the Merkle
    // leaf width is a per-scheme constant (`num_cols` of the committer
    // matrix), equal to the typed array width. Accepting shorter leaves
    // would only shift the failure from this assertion to the downstream
    // root check; asserting equality lets us use the cheaper fixed-size
    // hash.
    assert(leaf_size == MAX_LEAF_SIZE, "leaf_size must equal MAX_LEAF_SIZE");
    assert(path_len <= MAX_HEIGHT, "path_len exceeds max");

    // Step 1: Hash the leaf values (fixed-size, compile-time-unrolled)
    let mut current = hash_leaf_fixed(leaf_values);

    // Step 2: Walk up the tree
    let mut idx = index;
    for i in 0..MAX_HEIGHT {
        if (i as u32) < path_len {
            let sibling = siblings[i];
            let is_right = idx & 1;
            idx = idx >> 1;

            if is_right == 1 {
                // current is right child
                current = compress_2(sibling, current);
            } else {
                // current is left child
                current = compress_2(current, sibling);
            }
        }
    }

    // Step 3: Assert root match
    assert(current == root, "Merkle proof verification failed: root mismatch");
}

// =========================================================================
// Tests: equivalence between the fixed-size and variable-size sponge hash.
// =========================================================================

#[test]
fn hash_fixed_matches_variable_n_1() {
    let x: [Field; 1] = [42];
    assert(poseidon2_sponge_hash_fixed(x) == poseidon2_sponge_hash(x, 1));
}

#[test]
fn hash_fixed_matches_variable_n_2() {
    let x: [Field; 2] = [42, 17];
    assert(poseidon2_sponge_hash_fixed(x) == poseidon2_sponge_hash(x, 2));
}

#[test]
fn hash_fixed_matches_variable_n_3() {
    let x: [Field; 3] = [42, 17, 99];
    assert(poseidon2_sponge_hash_fixed(x) == poseidon2_sponge_hash(x, 3));
}

#[test]
fn hash_fixed_matches_variable_n_4() {
    let x: [Field; 4] = [1, 2, 3, 4];
    assert(poseidon2_sponge_hash_fixed(x) == poseidon2_sponge_hash(x, 4));
}

#[test]
fn hash_fixed_matches_variable_n_8() {
    let x: [Field; 8] = [11, 22, 33, 44, 55, 66, 77, 88];
    assert(poseidon2_sponge_hash_fixed(x) == poseidon2_sponge_hash(x, 8));
}

#[test]
fn hash_fixed_matches_variable_n_112() {
    let mut x: [Field; 112] = [0; 112];
    for i in 0..112 {
        x[i] = (i as Field) * 7 + 13;
    }
    assert(poseidon2_sponge_hash_fixed(x) == poseidon2_sponge_hash(x, 112));
}
