use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use cm31_ntt::ntt_utils::ntt_block_8;
use cm31_ntt::cm31::CF;
use num_traits::{Zero, One};
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

/// Run ntt_block_8 sequentially n times. The output of each run is used as the input for the next
/// run, so as to ensure that each run is performed sequentially.
fn sequential_ntt_block_8(inputs: [CF; 8], n: usize) -> [CF; 8] {
    let mut x = inputs;
    for _ in 0..n {
        x = ntt_block_8(
               black_box(inputs[0]), black_box(inputs[1]), 
               black_box(inputs[2]), black_box(inputs[3]),
               black_box(inputs[4]), black_box(inputs[5]),
               black_box(inputs[6]), black_box(inputs[7]), 
               CF::one(), CF::one(), CF::one(), CF::one(),
               CF::one(), CF::one(), CF::one(),
           );
    }
    x
}

fn benchmark(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let mut inputs = [CF::zero(); 8];
    for i in 0..8 {
        inputs[i] = rng.r#gen();
    }

    c.bench_function("sequential_ntt_block_8 2^24", |b| b.iter(|| sequential_ntt_block_8(black_box(inputs), 16777216)));
    c.bench_function("sequential_ntt_block_8 2^23", |b| b.iter(|| sequential_ntt_block_8(black_box(inputs), 7340032)));
    c.bench_function("sequential_ntt_block_8 2^22", |b| b.iter(|| sequential_ntt_block_8(black_box(inputs), 3670016)));
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(std::time::Duration::new(5,0))
        .measurement_time(std::time::Duration::new(30,0));
    targets = benchmark
);
criterion_main!(benches);
