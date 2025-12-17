/// Executable for profiling NTT
use {
    ark_bn254::Fr,
    ntt::{ntt_nr, NTT},
    std::hint::black_box,
};

fn main() {
    rayon::ThreadPoolBuilder::new().build_global().unwrap();

    let mut input = NTT::new(vec![Fr::from(1); 2_usize.pow(24)], 1).unwrap();
    ntt_nr(&mut input);
    black_box(input);
}
