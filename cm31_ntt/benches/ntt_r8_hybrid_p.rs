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
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_r8_hybrid_p");

    for log8_n in 7..9 {
        let n = 8usize.pow(log8_n);
        //let wn = get_root_of_unity(n);
        //let precomp_small = precomp_for_ntt_r8_ip_p(NTT_BLOCK_SIZE_FOR_CACHE, get_root_of_unity(NTT_BLOCK_SIZE_FOR_CACHE));
        //let precomp_full = gen_precomp_full(n, wn, NTT_BLOCK_SIZE_FOR_CACHE);

        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let mut f = vec![CF::zero(); n];
        for i in 0..n {
            f[i] = rng.r#gen();
        }

        let mut scratch = vec![CF::zero(); n];

        group.bench_function(format!("size {n}"), |b| {
            b.iter(|| {
                ntt_r8_hybrid_p(black_box(&f), &mut scratch, &*PRECOMP_SMALL, &*PRECOMP_FULL);
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

