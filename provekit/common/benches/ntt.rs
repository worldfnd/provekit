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

const RS_CASES: &[(u32, usize, usize, usize)] = &[
    (16, 2, 2, 1),
    (16, 2, 2, 32),
    (18, 2, 2, 1),
    (18, 2, 2, 32),
    (20, 2, 3, 1),
    (20, 2, 3, 32),
    (16, 4, 3, 1),
    (16, 4, 3, 32),
    (18, 4, 3, 1),
    (18, 4, 3, 32),
    (20, 4, 4, 1),
    (20, 4, 4, 32),
    (22, 4, 4, 1),
    (22, 4, 4, 32),
];

#[divan::bench(args = RS_CASES)]
fn provekit_rs(bencher: Bencher, case: &(u32, usize, usize, usize)) {
    let ntt = InPlaceNTT::<FieldElement>::default();
    bencher
        .with_inputs(|| {
            let (exp, expansion, coset_sz, num_polys) = *case;
            let mut rng = ark_std::test_rng();
            let total_size = 1 << exp;
            let poly_size = total_size / num_polys;
            let polys: Vec<Vec<FieldElement>> = (0..num_polys)
                .map(|_| {
                    (0..poly_size)
                        .map(|_| FieldElement::rand(&mut rng))
                        .collect()
                })
                .collect();
            (polys, expansion, coset_sz)
        })
        .bench_values(|(polys, expansion, coset_sz)| {
            let poly_refs: Vec<&[FieldElement]> = polys.iter().map(|p| p.as_slice()).collect();
            let poly_size = poly_refs[0].len();
            black_box(ntt.interleaved_encode(
                &poly_refs,
                (poly_size >> coset_sz) * expansion,
                1 << coset_sz,
            ))
        });
}

#[divan::bench(args = RS_CASES)]
fn ark_rs(bencher: Bencher, case: &(u32, usize, usize, usize)) {
    let ntt = ArkNtt::<FieldElement>::default();
    bencher
        .with_inputs(|| {
            let (exp, expansion, coset_sz, num_polys) = *case;
            let mut rng = ark_std::test_rng();
            let total_size = 1 << exp;
            let poly_size = total_size / num_polys;
            let polys: Vec<Vec<FieldElement>> = (0..num_polys)
                .map(|_| {
                    (0..poly_size)
                        .map(|_| FieldElement::rand(&mut rng))
                        .collect()
                })
                .collect();
            (polys, expansion, coset_sz)
        })
        .bench_values(|(polys, expansion, coset_sz)| {
            let poly_refs: Vec<&[FieldElement]> = polys.iter().map(|p| p.as_slice()).collect();
            let poly_size = poly_refs[0].len();
            black_box(ntt.interleaved_encode(
                &poly_refs,
                (poly_size >> coset_sz) * expansion,
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
