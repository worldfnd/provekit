use dep::poseidon2;

fn main(plains: [Field; 2]) -> pub Field {
    poseidon2::bn254::hash_2(plains)
}
