/// Executable for profiling NTT
use {
    ark_bn254::Fr,
    ntt::{init_roots_reverse_ordered, ntt},
    std::hint::black_box,
};

fn main() {
    rayon::ThreadPoolBuilder::new().build_global().unwrap();

    let mut input = vec![Fr::from(1); 2_usize.pow(24)];
    let roots = init_roots_reverse_ordered(input.len());
    ntt(&roots, &mut input);
    black_box(input);
}
