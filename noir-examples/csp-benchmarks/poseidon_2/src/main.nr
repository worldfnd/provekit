use poseidon::poseidon::bn254::hash_2;

fn main(inputs: [Field; 2]) -> pub Field {
    hash_2(inputs)
}
