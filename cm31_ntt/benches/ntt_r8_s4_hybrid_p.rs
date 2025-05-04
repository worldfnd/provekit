use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use cm31_ntt::ntt::*;
use cm31_ntt::cm31::CF;
use num_traits::Zero;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;
use lazy_static::lazy_static;

const N: usize = 8388608;

lazy_static! {
    static ref PRECOMP: PrecomputedTwiddles = {
        precompute_twiddles(N).unwrap()
    };
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_r8_s4_hybrid_p");

    let mut rng = ChaCha8Rng::seed_from_u64(0);

    let mut f = vec![CF::zero(); N];
    for i in 0..N {
        f[i] = rng.r#gen();
    }

    let mut scratch = vec![CF::zero(); NTT_BLOCK_SIZE_FOR_CACHE];

    group.bench_function(format!("size {N}"), |b| {
        b.iter(|| {
            let _ = ntt_r8_s4_hybrid_p(black_box(&f), &mut scratch, &*PRECOMP);
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
