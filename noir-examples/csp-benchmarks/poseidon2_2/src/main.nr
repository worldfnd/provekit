use poseidon2::bn254::permutation::t2;

fn main(inputs: [Field; 2]) -> pub Field {
    t2(inputs)[0]
}
