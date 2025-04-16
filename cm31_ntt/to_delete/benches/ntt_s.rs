use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use cm31_ntt::ntt_utils::{get_root_of_unity, precompute_twiddles};
use cm31_ntt::cm31::CF;
use cm31_ntt::ntt_s::*;
use num_traits::Zero;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

fn bench(c: &mut Criterion) {
    let radix = 8;
    let mut group = c.benchmark_group("NTT radix-8192");
    let w_64 = get_root_of_unity(64);

    for n in [8 * 8192] {
        let w = get_root_of_unity(n as usize);

        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let mut scratch = vec![CF::zero(); n];
        let mut arr = vec![CF::zero(); n];
        for i in 0..n {
            arr[i] = rng.r#gen();
        }

        group.bench_function(format!("ntt_mixed_8x8192"), |b| {
            b.iter(|| {
                ntt_mixed_8x8192(black_box(&mut arr), &mut scratch, w);
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
