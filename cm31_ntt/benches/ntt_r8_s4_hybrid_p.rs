use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use cm31_ntt::ntt_utils::get_root_of_unity;
use cm31_ntt::ntt::*;
use cm31_ntt::cm31::CF;
use num_traits::Zero;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;
use lazy_static::lazy_static;

lazy_static! {
    /// Cached small-block twiddle table (size = NTT_BLOCK_SIZE_FOR_CACHE)
    static ref PRECOMP_SMALL: Vec<CF> = {
        let n = NTT_BLOCK_SIZE_FOR_CACHE;
        let wn = get_root_of_unity(n);
        precomp_for_ntt_r8_ip_p(n, wn)
    };

    static ref PRECOMP_FULL: Vec<CF> = {
        let n = 8usize.pow(8);
        let wn = get_root_of_unity(n);
        gen_precomp_full(n, wn, NTT_BLOCK_SIZE_FOR_CACHE)
    };

    static ref PRECOMP_S4: Vec<CF> = {
        let n = 8usize.pow(8);
        precomp_s4(n)
    };
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_r8_s4_hybrid_p");

    for n in [8388608] {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let mut f = vec![CF::zero(); n];
        for i in 0..n {
            f[i] = rng.r#gen();
        }

        let mut scratch = vec![CF::zero(); NTT_BLOCK_SIZE_FOR_CACHE];

        group.bench_function(format!("size {n}"), |b| {
            b.iter(|| {
                ntt_r8_s4_hybrid_p(black_box(&f), &mut scratch, &*PRECOMP_SMALL, &*PRECOMP_FULL, &*PRECOMP_S4);
            })
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
}
criterion_main!(benches);


