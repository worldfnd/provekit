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

const RS_CASES: &[(u32, usize, usize)] = &[
    (16, 2, 2),
    (18, 2, 2),
    (20, 2, 3),
    (16, 4, 3),
    (18, 4, 3),
    (20, 4, 4),
    (22, 4, 4),
];

#[divan::bench(args = RS_CASES)]
fn provekit_rs(bencher: Bencher, case: &(u32, usize, usize)) {
    let ntt = InPlaceNTT::<FieldElement>::default();
    bencher
        .with_inputs(|| {
            let (exp, expansion, coset_sz) = *case;
            let mut rng = ark_std::test_rng();
            let size = 1 << exp;
            let coeffs: Vec<_> = (0..size).map(|_| FieldElement::rand(&mut rng)).collect();
            (coeffs, expansion, coset_sz)
        })
        .bench_values(|(coeffs, expansion, coset_sz)| {
            black_box(ntt.interleaved_encode(
                &[&coeffs],
                (coeffs.len() >> coset_sz) * expansion,
                1 << coset_sz,
            ))
        });
}

#[divan::bench(args = RS_CASES)]
fn ark_rs(bencher: Bencher, case: &(u32, usize, usize)) {
    let ntt = ArkNtt::<FieldElement>::default();
    bencher
        .with_inputs(|| {
            let (exp, expansion, coset_sz) = *case;
            let mut rng = ark_std::test_rng();
            let size = 1 << exp;
            let coeffs: Vec<_> = (0..size).map(|_| FieldElement::rand(&mut rng)).collect();
            (coeffs, expansion, coset_sz)
        })
        .bench_values(|(coeffs, expansion, coset_sz)| {
            black_box(ntt.interleaved_encode(
                &[&coeffs],
                (coeffs.len() >> coset_sz) * expansion,
                1 << coset_sz,
            ))
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
