use skyscraper_noir::compress;
use std::hash::poseidon2_permutation;

fn posseidon2_compress(l: Field, r: Field) -> Field {
    l + poseidon2_permutation([l, r], 2)[0]
}

fn main(l: pub Field, r: pub Field) -> pub Field {
    let mut h = l;
    for _ in 0..1 {
        h = compress(h, r);
    }
    h
}
