use poseidon2::bn254::permutation::t12;

fn main(inputs: [Field; 12]) -> pub Field {
    t12(inputs)[0]
}
