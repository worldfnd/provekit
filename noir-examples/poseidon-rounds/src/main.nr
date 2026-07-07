fn main(plains: [Field; 4]) -> pub [Field; 4] {
    let mut hash = std::hash::poseidon2_permutation(plains);
    let rounds = 1000;
    for _ in 0..rounds {
        hash = std::hash::poseidon2_permutation(hash);
    }
    hash
}
