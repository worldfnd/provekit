// Skyscraper Merkle Tree Verification
//
// Verifies Merkle inclusion proofs for WHIR commitment queries.
//
// Reference: recursive-verifier/app/circuit/whir_utilities.go (verifyMerkleTreeProofs)
//            provekit/common/src/skyscraper/whir.rs (SkyscraperHashEngine::hash_many)
//
// Leaf hashing: left-fold compress(acc, field[i]) over the leaf field elements.
// Node hashing: compress(left, right).
// Path verification: walk up using sibling hashes, select left/right by index bits.

use skyscraper_noir::compress;

/// Hash a prefix of field elements into a single Merkle leaf hash.
///
/// Equivalent to Rust's `elements.reduce(|acc, x| compress(acc, x))`.
/// For a single element (n_fields == 1), returns that element directly
/// (matches SkyscraperHashEngine::hash_many with size == 32).
fn hash_leaf<let MAX_LEAF_SIZE: u32>(
    fields: [Field; MAX_LEAF_SIZE],
    n_fields: u32,
) -> Field {
    assert(n_fields > 0, "leaf must have at least one element");
    assert(n_fields <= MAX_LEAF_SIZE, "n_fields exceeds MAX_LEAF_SIZE");

    let mut acc = fields[0];

    // For n_fields >= 2: acc = compress(f[0], f[1]), then fold remaining
    if n_fields >= 2 {
        acc = compress(fields[0], fields[1]);

        for i in 2..MAX_LEAF_SIZE {
            if (i as u32) < n_fields {
                acc = compress(acc, fields[i]);
            }
        }
    }

    acc
}

/// Verify a single Merkle inclusion proof.
///
/// - leaf_values: the field elements at this leaf
/// - leaf_size: number of actual field elements in the leaf
/// - siblings: sibling hashes along the path (bottom to top)
/// - path_len: number of levels in the path
/// - index: leaf index in the tree (used for left/right selection)
/// - root: expected Merkle root hash
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
                current = compress(sibling, current);
            } else {
                // current is left child
                current = compress(current, sibling);
            }
        }
    }

    // Step 3: Assert root match
    assert(current == root, "Merkle proof verification failed: root mismatch");
}
