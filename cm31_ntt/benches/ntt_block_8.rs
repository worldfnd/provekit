use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use cm31_ntt::ntt_utils::ntt_block_8;
use cm31_ntt::cm31::CF;
use num_traits::Zero;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

fn benchmark(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let mut inputs = [CF::zero(); 8];
    for i in 0..8 {
        inputs[i] = rng.r#gen();
    }

    c.bench_function("ntt_block_8", |b| b.iter(|| ntt_block_8(black_box(inputs))));
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10000)
        .warm_up_time(std::time::Duration::new(5,0))
        .measurement_time(std::time::Duration::new(20,0));
    targets = benchmark
);
criterion_main!(benches);
