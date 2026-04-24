use poseidon::poseidon2::Poseidon2;

fn main(inputs: [Field; 2]) -> pub Field {
    Poseidon2::hash(inputs, 2)
}
