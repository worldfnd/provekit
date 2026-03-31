/// Executable for profiling NTT
use {ark_bn254::Fr, ntt::ntt_nr, std::hint::black_box};

fn main() {
    rayon::ThreadPoolBuilder::new().build_global().unwrap();

    let mut input = vec![Fr::from(1); 2_usize.pow(24)];
    let codeword_size = input.len();
    ntt_nr(&mut input, codeword_size);
    black_box(input);
}
