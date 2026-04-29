use poseidon::poseidon::bn254::hash_8;

fn main(inputs: [Field; 8]) -> pub Field {
    hash_8(inputs)
}
