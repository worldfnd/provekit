// use poseidon::poseidon::bn254;

fn main(mut input: [Field; 4]) -> pub [Field; 4] {
    for _ in 0..10000 {
        input = std::hash::poseidon2_permutation(input, 4);
    }
    input
}
