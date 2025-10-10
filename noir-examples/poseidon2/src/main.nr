use poseidon::poseidon2::Poseidon2;
mod core;
mod poseidon2_constants;


mod bb {
    pub fn hash_1(xs: [Field; 1]) -> Field {
        std::hash::poseidon2::hash_1(xs)
    }
    pub fn hash_2(xs: [Field; 2]) -> Field {
        std::hash::poseidon2::hash_2(xs)
    }
}
mod mine {
    use super::core;

    pub fn hash_1(xs: [Field; 1]) -> Field {
        let state: [Field; 3] = [xs[0], 0, 0];
        let out = core::poseidon2_permute::<3>(state);
        out[0]
    }

    pub fn hash_2(xs: [Field; 2]) -> Field {
        let state: [Field; 3] = [xs[0], xs[1], 0];
        let out = core::poseidon2_permute::<3>(state);
        out[0]
    }
}


mod ext {
    

    pub fn hash_1(xs: [Field; 1]) -> Field {
        poseidon2::bn254::hash_1(xs)
    }
    pub fn hash_2(xs: [Field; 2]) -> Field {
        poseidon2::bn254::hash_2(xs)
    }
}
fn main() {

   // Can be empty

}

fn iterate_hash(mut h: Field, rounds: u32) -> Field {
    for _ in 0..rounds {
        h = bb::hash_1([h]);
    }
    h
}

// ----------------------- Tests -----------------------
#[test]
fn test_poseidon2_blackbox_vs_noir_vs_ext() {
    let cases: [[Field; 2]; 5] = [
        [1, 2],
        [3, 4],
        [5, 6],
        [123456789, 987654321],
        [0xdeadbeef, 0xcafebabe],
    ];

    for i in 0..5 {
        let plains = cases[i];

        // one-shot hash_2
        let bb   = bb::hash_2(plains);
        let mine = mine::hash_2(plains);
        let ext  = ext::hash_2(plains);

        println("bb   = ");  println(bb);
        println("mine = ");  println(mine);
        println("ext  = ");  println(ext);

        assert(bb == mine);
        assert(bb == ext);

        // stress: iterate hash_1 many times
        let rounds = 100u32;
        let bb_iter = iterate_hash(bb, rounds);

        let mut mine_iter = mine;
        let mut ext_iter  = ext;
        for _ in 0..rounds {
            mine_iter = mine::hash_1([mine_iter]);
            ext_iter  = ext::hash_1([ext_iter]);
        }

        println("bb_iter   = "); println(bb_iter);
        println("mine_iter = "); println(mine_iter);
        println("ext_iter  = "); println(ext_iter);

        assert(bb_iter == mine_iter);
        assert(bb_iter == ext_iter);
    }
}