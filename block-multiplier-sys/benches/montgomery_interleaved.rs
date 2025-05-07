#![feature(portable_simd)]
use {
    divan::{Bencher, black_box, counter::ItemsCount},
    fp_rounding::with_rounding_mode,
    rand::{Rng, rng},
    std::{array, simd::u64x2},
};

#[divan::bench]
fn montgomery_interleaved_3(bencher: Bencher) {
    let mut rng = rng();
    let a = array::from_fn(|_| rng.random());
    let b = array::from_fn(|_| rng.random());
    let av = array::from_fn(|_| u64x2::splat(rng.random()));
    let bv = array::from_fn(|_| u64x2::splat(rng.random()));

    // montgomery_interleaved_3
    unsafe {
        with_rounding_mode((), |mode_guard, _| {
            bencher.counter(ItemsCount::new(3usize)).bench_local(|| {
                block_multiplier_sys::montgomery_interleaved_3(
                    mode_guard,
                    black_box(a),
                    black_box(b),
                    black_box(av),
                    black_box(bv),
                )
            });
        });
    }
}

#[divan::bench]
fn montgomery_interleaved_4(bencher: Bencher) {
    let mut rng = rng();
    let a = array::from_fn(|_| rng.random());
    let a1 = array::from_fn(|_| rng.random());
    let b = array::from_fn(|_| rng.random());
    let b1 = array::from_fn(|_| rng.random());
    let av = array::from_fn(|_| u64x2::splat(rng.random()));
    let bv = array::from_fn(|_| u64x2::splat(rng.random()));

    unsafe {
        with_rounding_mode((), |mode_guard, _| {
            bencher.counter(ItemsCount::new(4usize)).bench_local(|| {
                block_multiplier_sys::montgomery_interleaved_4(
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
    }
}

fn main() {
    divan::main();
}
