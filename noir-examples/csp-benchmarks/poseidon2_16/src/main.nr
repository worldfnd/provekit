use poseidon2::bn254::permutation::t16;

fn main(inputs: [Field; 16]) -> pub Field {
    t16(inputs)[0]
}
