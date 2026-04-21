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

/// Poseidon2 2-to-1 compression: `sponge_hash([l, r], 2)`.
///
/// Specialized form: state = [l, r, 0, 2 * 2^64], one permute, return state[0].
pub fn compress_2(l: Field, r: Field) -> Field {
    let mut state: [Field; 4] = [l, r, 0, 2 * TWO_POW_64];
    state = poseidon2_permutation(state, 4);
    state[0]
}

/// Hash a prefix of field elements into a single Merkle leaf hash.
///
/// `n_fields` is the actual leaf width (may be less than MAX_LEAF_SIZE).
/// Matches `Poseidon2HashEngine::hash_many(size = n_fields * 32, ...)` on
/// the Rust side.
fn hash_leaf<let MAX_LEAF_SIZE: u32>(
    fields: [Field; MAX_LEAF_SIZE],
    n_fields: u32,
) -> Field {
    assert(n_fields > 0, "leaf must have at least one element");
    assert(n_fields <= MAX_LEAF_SIZE, "n_fields exceeds MAX_LEAF_SIZE");
    poseidon2_sponge_hash(fields, n_fields)
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
    assert(leaf_size <= MAX_LEAF_SIZE, "leaf_size exceeds max");
    assert(path_len <= MAX_HEIGHT, "path_len exceeds max");

    // Step 1: Hash the leaf values
    let mut current = hash_leaf(leaf_values, leaf_size);

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
