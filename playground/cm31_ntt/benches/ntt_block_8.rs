use {
    cm31_ntt::{cm31::CF, ntt_utils::ntt_block_8},
    criterion::{Criterion, criterion_group, criterion_main},
    num_traits::Zero,
    rand::Rng,
    rand_chacha::{ChaCha8Rng, rand_core::SeedableRng},
    std::hint::black_box,
};

fn benchmark(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let mut inputs = [CF::zero(); 8];
    for i in 0..8 {
        inputs[i] = rng.r#gen();
    }
    let wt: CF = rng.r#gen();
    let wt2: CF = rng.r#gen();
    let wt3: CF = rng.r#gen();
    let wt4: CF = rng.r#gen();
    let wt5: CF = rng.r#gen();
    let wt6: CF = rng.r#gen();
    let wt7: CF = rng.r#gen();

    c.bench_function("ntt_block_8", |b| {
        b.iter(|| {
            ntt_block_8(
                black_box(inputs[0]),
                black_box(inputs[1]),
                black_box(inputs[2]),
                black_box(inputs[3]),
                black_box(inputs[4]),
                black_box(inputs[5]),
                black_box(inputs[6]),
                black_box(inputs[7]),
                black_box(wt),
                black_box(wt2),
                black_box(wt3),
                black_box(wt4),
                black_box(wt5),
                black_box(wt6),
                black_box(wt7),
            )
        })
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10000)
        .measurement_time(std::time::Duration::new(10,0));
    targets = benchmark
);
criterion_main!(benches);
