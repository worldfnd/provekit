use poseidon::poseidon2::Poseidon2;

fn main(inputs: [Field; 12]) -> pub Field {
    Poseidon2::hash(inputs, 12)
}
