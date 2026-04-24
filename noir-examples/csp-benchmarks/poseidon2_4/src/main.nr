use poseidon::poseidon2::Poseidon2;

fn main(inputs: [Field; 4]) -> pub Field {
    Poseidon2::hash(inputs, 4)
}
