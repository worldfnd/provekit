use poseidon::poseidon::bn254::hash_4;

fn main(inputs: [Field; 4]) -> pub Field {
    hash_4(inputs)
}
