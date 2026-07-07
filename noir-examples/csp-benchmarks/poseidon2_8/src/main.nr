use poseidon2::bn254::permutation::t8;

fn main(inputs: [Field; 8]) -> pub Field {
    t8(inputs)[0]
}
