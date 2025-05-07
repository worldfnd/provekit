#![feature(portable_simd)]

use {
    core::{array, hint::black_box, simd::u64x2},
    divan::{Bencher, counter::ItemsCount},
    fp_rounding::with_rounding_mode,
    rand::{Rng, rng},
};

#[divan::bench_group]
mod mul {
    use super::*;

    #[divan::bench]
    fn scalar_mul(bencher: Bencher) {
        let mut rng = rng();
        let a = array::from_fn(|_| rng.random());
        let b = array::from_fn(|_| rng.random());
        bencher
            .counter(ItemsCount::new(1usize))
            .bench_local(|| block_multiplier::scalar_mul(black_box(a), black_box(b)));
    }

    #[divan::bench]
    fn simd_mul(bencher: Bencher) {
        let mut rng = rng();
        let a = array::from_fn(|_| rng.random());
        let b = array::from_fn(|_| rng.random());
        let c = array::from_fn(|_| rng.random());
        let d = array::from_fn(|_| rng.random());
        bencher.counter(ItemsCount::new(2usize)).bench_local(|| {
            block_multiplier::simd_mul(black_box(a), black_box(b), black_box(c), black_box(d))
        });
    }

    #[divan::bench]
    fn block_mul(bencher: Bencher) {
        let mut rng = rng();
        let a = array::from_fn(|_| rng.random());
        let b = array::from_fn(|_| rng.random());
        let c = array::from_fn(|_| rng.random());
        let d = array::from_fn(|_| rng.random());
        let e = array::from_fn(|_| rng.random());
        let f = array::from_fn(|_| rng.random());
        unsafe {
            with_rounding_mode((), |guard, _| {
                bencher.counter(ItemsCount::new(3usize)).bench_local(|| {
                    block_multiplier::block_mul(
                        guard,
                        black_box(a),
                        black_box(b),
                        black_box(c),
                        black_box(d),
                        black_box(e),
                        black_box(f),
                    )
                });
            });
        }
    }

    #[divan::bench]
    fn montgomery_interleaved_3(bencher: Bencher) {
        let mut rng = rng();
        let a = array::from_fn(|_| rng.random());
        let b = array::from_fn(|_| rng.random());
        let av = array::from_fn(|_| u64x2::splat(rng.random()));
        let bv = array::from_fn(|_| u64x2::splat(rng.random()));
        unsafe {
            with_rounding_mode((), |mode_guard, _| {
                bencher.counter(ItemsCount::new(3usize)).bench_local(|| {
                    block_multiplier::montgomery_interleaved_3(
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
                    block_multiplier::montgomery_interleaved_4(
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
}

#[divan::bench_group]
mod sqr {
    use super::*;

    #[divan::bench]
    fn scalar_sqr(bencher: Bencher) {
        let mut rng = rng();
        let a = array::from_fn(|_| rng.random());
        bencher
            .counter(ItemsCount::new(1usize))
            .bench_local(|| block_multiplier::scalar_sqr(black_box(a)));
    }

    #[divan::bench]
    fn simd_sqr(bencher: Bencher) {
        let mut rng = rng();
        let a = array::from_fn(|_| rng.random());
        let b = array::from_fn(|_| rng.random());
        bencher
            .counter(ItemsCount::new(2usize))
            .bench_local(|| block_multiplier::simd_sqr(black_box(a), black_box(b)));
    }

    #[divan::bench]
    fn block_sqr(bencher: Bencher) {
        let mut rng = rng();
        let a = array::from_fn(|_| rng.random());
        let b = array::from_fn(|_| rng.random());
        let c = array::from_fn(|_| rng.random());
        unsafe {
            with_rounding_mode((), |guard, _| {
                bencher.counter(ItemsCount::new(3usize)).bench_local(|| {
                    block_multiplier::block_sqr(guard, black_box(a), black_box(b), black_box(c))
                });
            });
        }
    }
}

fn main() {
    divan::main();
}
