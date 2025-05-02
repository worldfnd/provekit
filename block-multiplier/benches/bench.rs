use {
    criterion::{Criterion, black_box, criterion_group, criterion_main},
    rand::{Rng, SeedableRng, prelude::StdRng},
};

fn bench_block_multiplier(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_multiplier");

    let seed: u64 = rand::random();
    println!("Using random seed for benchmark: {}", seed);
    let mut rng = StdRng::seed_from_u64(seed);

    let s0_a = [
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
    ];
    let s0_b = [
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
    ];

    let v0_a = [
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
    ];
    let v0_b = [
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
    ];
    let v1_a = [
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
    ];
    let v1_b = [
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
    ];

    let rtz = rtz::RTZ::set().unwrap();

    group.bench_function("scalar_mul", |bencher| {
        bencher.iter(|| block_multiplier::scalar_mul(black_box(s0_a), black_box(s0_b)))
    });

    group.bench_function("scalar_sqr", |bencher| {
        bencher.iter(|| block_multiplier::scalar_sqr(black_box(s0_a)))
    });

    group.bench_function("simd_sqr", |bencher| {
        bencher.iter(|| block_multiplier::simd_sqr(black_box(v0_a), black_box(v1_a)))
    });

    group.bench_function("simd_mul", |bencher| {
        bencher.iter(|| {
            block_multiplier::simd_mul(
                black_box(v0_a),
                black_box(v0_b),
                black_box(v1_a),
                black_box(v1_b),
            )
        })
    });

    group.bench_function("block_mul", |bencher| {
        bencher.iter(|| {
            block_multiplier::block_mul(
                &rtz,
                black_box(s0_a),
                black_box(s0_b),
                black_box(v0_a),
                black_box(v0_b),
                black_box(v1_a),
                black_box(v1_b),
            )
        })
    });

    group.bench_function("block_sqr", |bencher| {
        bencher.iter(|| {
            block_multiplier::block_sqr(&rtz, black_box(s0_a), black_box(v0_a), black_box(v1_a))
        })
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(5000)
        // Warm up is warm because it literally warms up the pi
        .warm_up_time(std::time::Duration::new(1,0))
        .measurement_time(std::time::Duration::new(10,0));
    targets = bench_block_multiplier
);
criterion_main!(benches);
