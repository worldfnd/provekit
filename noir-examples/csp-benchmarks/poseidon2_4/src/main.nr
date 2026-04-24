use std::hash::poseidon2_permutation;

fn main(inputs: [Field; 4]) -> pub Field {
    poseidon2_permutation(inputs, 4)[0]
}
