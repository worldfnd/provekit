/// 1000 iterations of Poseidon2 permutation (width 4).
fn main(input: pub [Field; 4]) -> pub [Field; 4] {
    let mut state = input;
    for _ in 0..1000 {
        state = std::hash::poseidon2_permutation(state, 4);
    }
    state
}
