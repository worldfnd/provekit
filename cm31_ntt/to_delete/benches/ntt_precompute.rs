use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use cm31_ntt::ntt_utils::{get_root_of_unity, precompute_twiddles};
use cm31_ntt::ntt::{ntt_radix_8, ntt_radix_8_precomputed};
use cm31_ntt::cm31::CF;
use num_traits::Zero;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

fn bench_with_and_without_precomputation(c: &mut Criterion) {
    let radix = 8;

    let mut sizes = vec![];
    for i in 4..7 {
        sizes.push((8usize).pow(i));
    }

    let mut group = c.benchmark_group("NTT");
    for n in sizes {
        let w = get_root_of_unity(n as usize);

        let twiddles = precompute_twiddles(n as usize, w, radix);

        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let mut f = vec![CF::zero(); n];
        for i in 0..n {
            f[i] = rng.r#gen();
        }

        group.bench_function(format!("size {n} without precomputation"), |b| {
            b.iter(|| {
                let f_clone = f.clone();
                ntt_radix_8(black_box(f_clone), w);
            })
        });
        group.bench_function(format!("size {n} with precomputation"), |b| {
            b.iter(|| {
                let f_clone = f.clone();
                ntt_radix_8_precomputed(black_box(f_clone), &twiddles);
            })
        });
    }
    group.finish();
}


criterion_group!(benches, bench_with_and_without_precomputation);
criterion_main!(benches);
