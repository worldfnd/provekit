use poseidon::poseidon::bn254::hash_16;

fn main(inputs: [Field; 16]) -> pub Field {
    hash_16(inputs)
}
