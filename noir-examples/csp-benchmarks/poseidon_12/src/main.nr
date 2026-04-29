use poseidon::poseidon::bn254::hash_12;

fn main(inputs: [Field; 12]) -> pub Field {
    hash_12(inputs)
}
