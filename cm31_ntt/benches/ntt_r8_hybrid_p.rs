use {
    cm31_ntt::{cm31::CF, ntt::*},
    criterion::{Criterion, criterion_group, criterion_main},
    lazy_static::lazy_static,
    num_traits::Zero,
    rand::Rng,
    rand_chacha::{ChaCha8Rng, rand_core::SeedableRng},
    std::hint::black_box,
};

lazy_static! {
    static ref PRECOMP_7: PrecomputedTwiddles = {
        let n = 8usize.pow(7);
        precompute_twiddles(n).unwrap()
    };
    static ref PRECOMP_8: PrecomputedTwiddles = {
        let n = 8usize.pow(8);
        precompute_twiddles(n).unwrap()
    };
}

fn bench(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    let mut group = c.benchmark_group("ntt_r8_hybrid_p");

    // 8 ^ 7
    let n = 8usize.pow(7);

    let mut f = vec![CF::zero(); n];
    for i in 0..n {
        f[i] = rng.r#gen();
    }

    let mut scratch = vec![CF::zero(); NTT_BLOCK_SIZE_FOR_CACHE];

    group.bench_function(format!("size {n}"), |b| {
        b.iter(|| {
            let _ = ntt_r8_hybrid_p(black_box(&f), &mut scratch, &*PRECOMP_7);
        })
    });

    // 8 ^ 8

    let n = 8usize.pow(8);

    let mut f = vec![CF::zero(); n];
    for i in 0..n {
        f[i] = rng.r#gen();
    }

    let mut scratch = vec![CF::zero(); NTT_BLOCK_SIZE_FOR_CACHE];

    group.bench_function(format!("size {n}"), |b| {
        b.iter(|| {
            let _ = ntt_r8_hybrid_p(black_box(&f), &mut scratch, &*PRECOMP_8);
        })
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
}
criterion_main!(benches);
