use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use cm31_ntt::ntt_optimisation_attempt::ntt_radix_8_in_place;
use cm31_ntt::ntt_utils::{get_root_of_unity, precompute_twiddles};
use cm31_ntt::cm31::CF;
use num_traits::Zero;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("NTT (in-place)");
    let radix = 8;

    for n in [64, 4096, 262144, 16777216] {
        let w = get_root_of_unity(n as usize);
        let twiddles = precompute_twiddles(n as usize, w, radix);

        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let mut arr = vec![CF::zero(); n];
        for i in 0..n {
            arr[i] = rng.r#gen();
        }

        //group.bench_function(format!("size {n} with precomputation (in-place)"), |b| {
            //b.iter(|| {
                //ntt_radix_8_in_place_precomputed(black_box(&mut arr), &twiddles);
            //})
        //});

        group.bench_function(format!("size {n} without precomputation (in-place)"), |b| {
            b.iter(|| {
                ntt_radix_8_in_place(black_box(&mut arr), w);
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
