use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::prelude::StdRng;
use rand::{Rng, SeedableRng};

fn bench_skyscraper(c: &mut Criterion) {
    let mut group = c.benchmark_group("skyscraper");
    let seed: u64 = rand::random();
    println!("Using random seed for benchmark: {}", seed);
    let mut rng = StdRng::seed_from_u64(seed);

    let l_0 = [
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
    ];
    let l_1 = [
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
    ];
    let l_2 = [
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
    ];
    let r_0 = [
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
    ];
    let r_1 = [
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
    ];
    let r_2 = [
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
        rng.random::<u64>(),
    ];

    let _rtz = block_multiplier::rtz::RTZ::set().unwrap();

    group.bench_function("compress", |bencher| {
        bencher.iter(|| skyscraper::compress(black_box(l_0), black_box(r_0)))
    });

    group.bench_function("block_compress", |bencher| {
        bencher.iter(|| skyscraper::block_compress(
            black_box(&_rtz),
            black_box(l_0),
            black_box(l_1),
            black_box(l_2),
            black_box(r_0),
            black_box(r_1),
            black_box(r_2)
        ))
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(5000)
        // Warm up is warm because it literally warms up the pi
        .warm_up_time(std::time::Duration::new(1,0))
        .measurement_time(std::time::Duration::new(10,0));
    targets = bench_skyscraper
);
criterion_main!(benches);
