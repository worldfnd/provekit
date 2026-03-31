use {
    ark_bn254::Fr,
    ark_ff::UniformRand,
    divan::{black_box, Bencher},
    provekit_common::ntt::RSFr,
    whir::algebra::ntt::{NttEngine, ReedSolomon},
};

// (exp, expansion, coset_sz): matches whir's expand_from_coeff bench cases.
// message_length = 2^(exp - coset_sz), num_messages = 2^coset_sz,
// codeword_length = message_length * expansion.
const TEST_CASES: &[(usize, usize, usize)] = &[
    (16, 2, 2),
    (18, 2, 2),
    (20, 2, 3),
    (16, 4, 3),
    (18, 4, 3),
    (20, 4, 4),
    (22, 4, 4),
];

fn make_messages(exp: usize, coset_sz: usize) -> Vec<Vec<Fr>> {
    let message_length = 1 << (exp - coset_sz);
    let num_messages = 1 << coset_sz;
    let mut rng = ark_std::rand::thread_rng();
    (0..num_messages)
        .map(|_| (0..message_length).map(|_| Fr::rand(&mut rng)).collect())
        .collect()
}

#[divan::bench(args = TEST_CASES)]
fn rs_fr(bencher: Bencher, case: &(usize, usize, usize)) {
    let (exp, expansion, coset_sz) = *case;
    bencher
        .with_inputs(|| make_messages(exp, coset_sz))
        .bench_values(|coeffs| {
            let refs: Vec<&[Fr]> = coeffs.iter().map(Vec::as_slice).collect();
            let codeword_length = refs[0].len() * expansion;
            black_box(RSFr.interleaved_encode(&refs, &[], codeword_length))
        });
}

#[divan::bench(args = TEST_CASES)]
fn whir_ntt_engine(bencher: Bencher, case: &(usize, usize, usize)) {
    let (exp, expansion, coset_sz) = *case;
    let reference = NttEngine::<Fr>::new_from_fftfield();
    bencher
        .with_inputs(|| make_messages(exp, coset_sz))
        .bench_values(|coeffs| {
            let refs: Vec<&[Fr]> = coeffs.iter().map(Vec::as_slice).collect();
            let codeword_length = refs[0].len() * expansion;
            black_box(reference.interleaved_encode(&refs, &[], codeword_length))
        });
}

fn main() {
    divan::main();
}
