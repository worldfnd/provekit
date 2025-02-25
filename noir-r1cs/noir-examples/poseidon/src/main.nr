use dep::poseidon2;

fn main(plains: [Field; 8], result: Field) {
    let hash = poseidon2::bn254::hash_8(plains);
    print(hash);
    assert(result == hash);
}
