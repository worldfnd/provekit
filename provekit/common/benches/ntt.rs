use {
    ark_bn254::Fr as FieldElement,
    ark_std::UniformRand,
    divan::{black_box, Bencher},
    ntt::{ntt_nr, NTT},
    provekit_common::InPlaceNTT,
    whir::algebra::ntt::{ntt_batch, ArkNtt, ReedSolomon},
};

fn main() {
    divan::main();
}

// (log2 of per-polynomial NTT size, number of polynomials)
const NTT_CASES: &[(u32, usize)] = &[(22, 1), (24, 1)];

// (poly_size_log2, expansion, interleaving_depth_log2)
const RS_CASES: &[(u32, usize, u32)] = &[(22, 2, 4)];

#[divan::bench(args = RS_CASES)]
fn provekit_rs(bencher: Bencher, &(log_n, expansion, log_depth): &(u32, usize, u32)) {
    let ntt = InPlaceNTT::<FieldElement>::default();
    bencher
        .with_inputs(|| {
            let mut rng = ark_std::test_rng();
            let coeffs: Vec<FieldElement> = (0..1usize << log_n)
                .map(|_| FieldElement::rand(&mut rng))
                .collect();
            (coeffs, expansion, 1usize << log_depth)
        })
        .bench_values(|(coeffs, expansion, depth)| {
            black_box(ntt.interleaved_encode(&[&coeffs, &coeffs, &coeffs], expansion, depth))
        });
}

#[divan::bench(args = RS_CASES)]
fn ark_rs(bencher: Bencher, &(log_n, expansion, log_depth): &(u32, usize, u32)) {
    let ntt = ArkNtt::<FieldElement>::default();
    bencher
        .with_inputs(|| {
            let mut rng = ark_std::test_rng();
            let coeffs: Vec<FieldElement> = (0..1usize << log_n)
                .map(|_| FieldElement::rand(&mut rng))
                .collect();
            (coeffs, expansion, 1usize << log_depth)
        })
        .bench_values(|(coeffs, expansion, depth)| {
            black_box(ntt.interleaved_encode(&[&coeffs, &coeffs, &coeffs], expansion, depth))
        });
}

#[divan::bench(args = NTT_CASES)]
fn whir_ntt_batch(bencher: Bencher, &(log_n, num_polys): &(u32, usize)) {
    bencher
        .with_inputs(|| {
            let mut rng = ark_std::test_rng();
            (0..num_polys * (1usize << log_n))
                .map(|_| FieldElement::rand(&mut rng))
                .collect::<Vec<_>>()
        })
        .bench_values(|mut values| {
            ntt_batch(&mut values, 1 << log_n);
            black_box(values)
        });
}

#[divan::bench(args = NTT_CASES)]
fn provekit_ntt_nr(bencher: Bencher, &(log_n, num_polys): &(u32, usize)) {
    bencher
        .with_inputs(|| {
            let mut rng = ark_std::test_rng();
            let values: Vec<FieldElement> = (0..num_polys * (1usize << log_n))
                .map(|_| FieldElement::rand(&mut rng))
                .collect();
            NTT::new(values, num_polys).unwrap()
        })
        .bench_values(|mut ntt| {
            ntt_nr(&mut ntt);
            black_box(ntt)
        });
}
