use dep::poseidon2;

fn main(plains: [Field; 2], result: Field) {
    let mut hash = poseidon2::bn254::hash_2(plains);
    let rounds = 100;
    for _ in 0..rounds {
        hash = poseidon2::bn254::hash_1([hash]);
    }
    println(hash);
    assert(hash == result);
}
