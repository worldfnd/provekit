use dep::poseidon2;

mod bb_poseidon2;

mod ext {

    pub fn hash_2(xs: [Field; 2]) -> Field {
        poseidon2::bn254::hash_2(xs)
    }
    pub fn hash_4(xs: [Field; 4]) -> Field {
        poseidon2::bn254::hash_4(xs)
    }
    pub fn hash_8(xs: [Field; 8]) -> Field {
        poseidon2::bn254::hash_8(xs)
    }
    pub fn hash_12(xs: [Field; 12]) -> Field {
        poseidon2::bn254::hash_12(xs)
    }
    pub fn hash_16(xs: [Field; 16]) -> Field {
        poseidon2::bn254::hash_16(xs)
    }
}
// Return the permuted state publicly
fn main(st: pub [Field; 4]) -> pub [Field; 4] {
    std::hash::poseidon2_permutation(st, 4)
}

// ----------------------- Tests -----------------------
#[test]
fn test_poseidon2_blackbox_vs_ext() {
    let cases: [[Field; 4]; 5] = [
        [1, 2, 1, 2],
        [3, 4, 3, 4],
        [5, 6, 5, 6],
        [123456789, 987654321, 123456789, 987654321],
        [0xdeadbeef, 0xcafebabe, 0xdeadbeef, 0xcafebabe],
    ];

    for i in 0..5 {
        let plains = cases[i];

        let ext = ext::hash_4(plains);
        let bb = bb_poseidon2::bb::bb_perm4(plains)[0];

        println("bb = ");
        println(bb);
        println("ext  = ");
        println(ext);

        assert(ext == bb);
    }
}
