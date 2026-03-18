fn main(plains: [Field; 4], result: Field) -> pub [Field; 4] {
    let mut hash = std::hash::poseidon2_permutation(plains, 4);
    let rounds = 1000;
    for _ in 0..rounds {
        hash = std::hash::poseidon2_permutation(hash, 4);
    }
    hash
}
