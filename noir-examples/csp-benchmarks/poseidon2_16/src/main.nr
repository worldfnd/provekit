use poseidon::poseidon2::Poseidon2;

fn main(inputs: [Field; 16]) -> pub Field {
    Poseidon2::hash(inputs, 16)
}
