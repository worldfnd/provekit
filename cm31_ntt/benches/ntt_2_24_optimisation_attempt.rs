use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use cm31_ntt::ntt_optimisation_attempt::ntt_radix_8_in_place;
use cm31_ntt::ntt_utils::{get_root_of_unity, precompute_twiddles};
use cm31_ntt::cm31::CF;
use num_traits::Zero;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

fn bench_2_24(c: &mut Criterion) {
    let radix = 8;

    let n = 16777216; // 2^24
    let w = get_root_of_unity(n as usize);
    let twiddles = precompute_twiddles(n as usize, w, radix);

    let mut group = c.benchmark_group("NTT (2^24)");

    let mut rng = ChaCha8Rng::seed_from_u64(0);

    let mut arr = vec![CF::zero(); 16777216];
    for i in 0..n {
        arr[i] = rng.r#gen();
    }

    group.bench_function(format!("size {n} with precomputation (in-place)"), |b| {
        b.iter(|| {
            ntt_radix_8_in_place(black_box(&mut arr), &twiddles);
        })
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_2_24
}
criterion_main!(benches);
