use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use cm31_ntt::ntt_utils::get_root_of_unity;
use cm31_ntt::ntt::*;
use cm31_ntt::cm31::CF;
use num_traits::Zero;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_r8_hybrid_ps");

    for log8_n in 7..9 {
        let n = 8usize.pow(log8_n);
        let wn = get_root_of_unity(n as usize);
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let mut f = vec![CF::zero(); n];
        for i in 0..n {
            f[i] = rng.r#gen();
        }
        // TODO: refactor
        let precomp_small = if n < NTT_BLOCK_SIZE_FOR_CACHE {
            precomp_for_ntt_r8_ip_p(n, wn)
        } else {
            precomp_for_ntt_r8_ip_p(NTT_BLOCK_SIZE_FOR_CACHE, get_root_of_unity(NTT_BLOCK_SIZE_FOR_CACHE))
        };

        group.bench_function(format!("size {n}"), |b| {
            b.iter(|| {
                ntt_r8_hybrid_ps(black_box(&f), wn, &precomp_small);
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

