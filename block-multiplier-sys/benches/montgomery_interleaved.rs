#![feature(portable_simd)]
use {
    block_multiplier_sys::{montgomery_interleaved_3, montgomery_interleaved_4},
    criterion::{Criterion, black_box, criterion_group, criterion_main},
    fp_rounding::with_rounding_mode,
    rand::{Rng, SeedableRng, rngs::StdRng},
    std::{array, simd::u64x2},
}; // Use u64x2 directly

fn bench_montgomery_interleaved(c: &mut Criterion) {
    // Setup common data
    let seed: u64 = rand::random();
    println!("Using random seed for benchmark: {seed}");
    let mut rng = StdRng::seed_from_u64(seed);

    let a = array::from_fn(|_| rng.random());
    let a1 = array::from_fn(|_| rng.random());
    let b = array::from_fn(|_| rng.random());
    let b1 = array::from_fn(|_| rng.random());
    let av = array::from_fn(|_| u64x2::splat(rng.random()));
    let bv = array::from_fn(|_| u64x2::splat(rng.random()));

    c.bench_function("montgomery_interleaved_3", |bench| unsafe {
        with_rounding_mode((), |mode_guard, _| {
            bench.iter(|| {
                montgomery_interleaved_3(
                    mode_guard,
                    black_box(a),
                    black_box(b),
                    black_box(av),
                    black_box(bv),
                )
            });
        });
    });

    c.bench_function("montgomery_interleaved_4", |bench| unsafe {
        with_rounding_mode((), |mode_guard, _| {
            bench.iter(|| {
                montgomery_interleaved_4(
                    mode_guard,
                    black_box(a),
                    black_box(b),
                    black_box(a1),
                    black_box(b1),
                    black_box(av),
                    black_box(bv),
                )
            });
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .without_plots()
        .sample_size(5000)
        .warm_up_time(std::time::Duration::new(1,0))
        .measurement_time(std::time::Duration::new(10,0));
    targets = bench_montgomery_interleaved
);
criterion_main!(benches);
