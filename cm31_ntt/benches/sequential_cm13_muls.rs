use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use cm31_ntt::cm31::CF;
use num_traits::Zero;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

/// Perform n * 7 CM13 multiplications sequentially.
fn sequential_cm13_muls(inputs: [CF; 7], multiplier: CF, n: usize) -> [CF; 7] {
    let mut x = inputs;
    for _ in 0..n {
        for j in 0..7 {
            x[j] = x[j] * multiplier;
        }
    }
    x
}

fn benchmark(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let mut inputs = [CF::zero(); 7];
    for i in 0..7 {
        inputs[i] = rng.r#gen();
    }

    let multiplier: CF = rng.r#gen();
    c.bench_function("sequential_cm13_muls 2^24", |b| b.iter(|| sequential_cm13_muls(black_box(inputs), black_box(multiplier), 16777216)));
    c.bench_function("sequential_cm13_muls 2^23", |b| b.iter(|| sequential_cm13_muls(black_box(inputs), black_box(multiplier), 7340032)));
    c.bench_function("sequential_cm13_muls 2^22", |b| b.iter(|| sequential_cm13_muls(black_box(inputs), black_box(multiplier), 3670016)));
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(std::time::Duration::new(5,0))
        .measurement_time(std::time::Duration::new(50,0));
    targets = benchmark
);
criterion_main!(benches);
