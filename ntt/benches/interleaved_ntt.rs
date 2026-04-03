use {
    ark_bn254::Fr,
    ark_ff::UniformRand,
    divan::{black_box, Bencher},
    ntt::{ark_interleaved::ntt_nr_ark, b51_interleaved::ntt_nr_b51},
};

// (codeword_size_log2, num_groups_log2)
// total values = 2^(codeword_log2 + num_groups_log2)
const TEST_CASES: &[(usize, usize)] = &[
    (16, 0),
    (18, 0),
    (20, 0),
    (16, 2),
    (18, 2),
    (20, 2),
    // (20, 3),
    // (22, 3),
];

fn make_values(codeword_log2: usize, num_groups_log2: usize) -> Vec<Fr> {
    let total = 1 << (codeword_log2 + num_groups_log2);
    let mut rng = ark_std::test_rng();
    (0..total).map(|_| Fr::rand(&mut rng)).collect()
}

#[divan::bench(args = TEST_CASES)]
fn ark(bencher: Bencher, case: &(usize, usize)) {
    let (codeword_log2, num_groups_log2) = *case;
    let codeword_size = 1 << codeword_log2;
    let num_groups = 1 << num_groups_log2;
    bencher
        .with_inputs(|| make_values(codeword_log2, num_groups_log2))
        .bench_values(|mut values| ntt_nr_ark(black_box(&mut values), codeword_size, num_groups));
}

#[divan::bench(args = TEST_CASES)]
fn b51(bencher: Bencher, case: &(usize, usize)) {
    let (codeword_log2, num_groups_log2) = *case;
    let codeword_size = 1 << codeword_log2;
    let num_groups = 1 << num_groups_log2;
    bencher
        .with_inputs(|| make_values(codeword_log2, num_groups_log2))
        .bench_values(|mut values| ntt_nr_b51(black_box(&mut values), codeword_size, num_groups));
}

fn main() {
    divan::main();
}
