use dep::poseidon2;

fn main(plains: [Field; 2], result: Field) {
    let hash = poseidon2::bn254::permutation::t2(plains)[0];
    print(hash);
    assert(hash == result);
}
