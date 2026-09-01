use dep::poseidon2;

fn main(plains: [Field; 2], result: Field) {
    let mut hash = poseidon2::bn254::permutation::t2(plains)[0];
    let rounds = 1000;
    for _ in 0..rounds {
        hash = poseidon2::bn254::permutation::t2([hash, 1])[0];
    }
    println(hash);
    assert(hash == result);
}
