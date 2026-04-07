fn main(
    leaf: pub Field,
) -> pub Field {
    // Compute Merkle root for a tree of depth 24 with the leaf at index 0
    // and all-zero sibling hashes
    let zero_path: [Field; 24] = [0; 24];
    let mut current = leaf;
    for i in 0..24 {
        current = poseidon::poseidon2::Poseidon2::hash([current, zero_path[i]], 2);
    }
    current
}
