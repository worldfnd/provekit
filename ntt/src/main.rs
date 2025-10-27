/// Executable for profiling NTT
use {
    ark_bn254::Fr,
    ntt::{NTTEngine, NTT},
    std::hint::black_box,
};

fn main() {
    rayon::ThreadPoolBuilder::new().build_global().unwrap();

    let mut input = NTT::new(vec![Fr::from(1); 2_usize.pow(24)]).unwrap();
    let mut engine = NTTEngine::with_order(input.order());
    engine.ntt_nr(&mut input);
    black_box(input);
}
