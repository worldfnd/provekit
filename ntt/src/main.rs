/// Executable for profiling NTT
use {
    ark_bn254::Fr,
    ntt::{init_roots_reverse_ordered, ntt_nr, NTTEngine, NTT},
    std::hint::black_box,
};

fn main() {
    rayon::ThreadPoolBuilder::new().build_global().unwrap();

    let mut input = NTT::new(vec![Fr::from(1); 2_usize.pow(24)]).unwrap();
    let roots = init_roots_reverse_ordered(input.len());
    ntt_nr(&roots, &mut input);
    let mut input = black_box(input);

    // let mut engine = NTTEngine::new(input.len());
    // engine.ntt_nr(&mut input);
    // black_box(input);
}
