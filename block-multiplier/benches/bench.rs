#![feature(portable_simd)]

use {
    core::{array, simd::u64x2},
    divan::Bencher,
    fp_rounding::with_rounding_mode,
    rand::{Rng, rng},
};

// #[divan::bench_group]
mod mul {
    use super::*;

    #[divan::bench]
    fn scalar_mul(bencher: Bencher) {
        bencher
            //.counter(ItemsCount::new(1usize))
            .with_inputs(|| rng().random())
            .bench_local_values(|(a, b)| block_multiplier::scalar_mul(a, b));
    }

    #[divan::bench]
    fn ark_ff(bencher: Bencher) {
        use {ark_bn254::Fr, ark_ff::BigInt};
        bencher
            //.counter(ItemsCount::new(1usize))
            .with_inputs(|| {
                (
                    Fr::new(BigInt(rng().random())),
                    Fr::new(BigInt(rng().random())),
                )
            })
            .bench_local_values(|(a, b)| a * b);
    }

    #[divan::bench]
    fn simd_mul(bencher: Bencher) {
        bencher
            //.counter(ItemsCount::new(2usize))
            .with_inputs(|| rng().random())
            .bench_local_values(|(a, b, c, d)| block_multiplier::simd_mul(a, b, c, d));
    }

    #[divan::bench]
    fn block_mul(bencher: Bencher) {
        let bencher = bencher
            //.counter(ItemsCount::new(3usize))
            .with_inputs(|| rng().random());
        unsafe {
            with_rounding_mode((), |guard, _| {
                bencher.bench_local_values(|(a, b, c, d, e, f)| {
                    block_multiplier::block_mul(guard, a, b, c, d, e, f)
                });
            });
        }
    }

    #[divan::bench]
    fn montgomery_interleaved_3(bencher: Bencher) {
        let bencher = bencher
            //.counter(ItemsCount::new(3usize))
            .with_inputs(|| {
                (
                    rng().random(),
                    rng().random(),
                    array::from_fn(|_| u64x2::from_array(rng().random())),
                    array::from_fn(|_| u64x2::from_array(rng().random())),
                )
            });
        unsafe {
            with_rounding_mode((), |mode_guard, _| {
                bencher.bench_local_values(|(a, b, c, d)| {
                    block_multiplier::montgomery_interleaved_3(mode_guard, a, b, c, d)
                });
            });
        }
    }

    #[divan::bench]
    fn montgomery_interleaved_4(bencher: Bencher) {
        let bencher = bencher
            //.counter(ItemsCount::new(4usize))
            .with_inputs(|| {
                (
                    rng().random(),
                    rng().random(),
                    rng().random(),
                    rng().random(),
                    array::from_fn(|_| u64x2::from_array(rng().random())),
                    array::from_fn(|_| u64x2::from_array(rng().random())),
                )
            });
        unsafe {
            with_rounding_mode((), |mode_guard, _| {
                bencher.bench_local_values(|(a, b, c, d, e, f)| {
                    block_multiplier::montgomery_interleaved_4(mode_guard, a, b, c, d, e, f)
                });
            });
        }
    }
}

// #[divan::bench_group]
mod sqr {
    use {super::*, ark_ff::Field};

    #[divan::bench]
    fn scalar_sqr(bencher: Bencher) {
        bencher
            //.counter(ItemsCount::new(1usize))
            .with_inputs(|| rng().random())
            .bench_local_values(block_multiplier::scalar_sqr);
    }

    #[divan::bench]
    fn ark_ff(bencher: Bencher) {
        use {ark_bn254::Fr, ark_ff::BigInt};
        bencher
            //.counter(ItemsCount::new(1usize))
            .with_inputs(|| Fr::new(BigInt(rng().random())))
            .bench_local_values(|a: Fr| a.square());
    }

    #[divan::bench]
    fn montgomery_square_log_interleaved_3(bencher: Bencher) {
        let bencher = bencher
            .with_inputs(|| {
                (
                    rng().random(),
                    array::from_fn(|_| u64x2::from_array(rng().random())),
                )
            });
        unsafe {
            with_rounding_mode((), |mode_guard, _| {
                bencher.bench_local_values(|(a, b)| {
                    block_multiplier::montgomery_square_log_interleaved_3(mode_guard, a, b)
                });
            });
        }
    }

    #[divan::bench]
    fn montgomery_square_log_interleaved_4(bencher: Bencher) {
        let bencher = bencher
            .with_inputs(|| {
                (
                    rng().random(),
                    rng().random(),
                    array::from_fn(|_| u64x2::from_array(rng().random())),
                )
            });
        unsafe {
            with_rounding_mode((), |mode_guard, _| {
                bencher.bench_local_values(|(a, b, c)| {
                    block_multiplier::montgomery_square_log_interleaved_4(mode_guard, a, b, c)
                });
            });
        }

        #[divan::bench]
        fn montgomery_square_interleaved_3(bencher: Bencher) {
            let bencher = bencher
                .with_inputs(|| {
                    (
                        rng().random(),
                        array::from_fn(|_| u64x2::from_array(rng().random())),
                    )
                });
            unsafe {
                with_rounding_mode((), |mode_guard, _| {
                    bencher.bench_local_values(|(a, b)| {
                        block_multiplier::montgomery_square_interleaved_3(mode_guard, a, b)
                    });
                });
            }
        }

        #[divan::bench]
        fn montgomery_square_interleaved_4(bencher: Bencher) {
            let bencher = bencher
                .with_inputs(|| {
                    (
                        rng().random(),
                        rng().random(),
                        array::from_fn(|_| u64x2::from_array(rng().random())),
                    )
                });
            unsafe {
                with_rounding_mode((), |mode_guard, _| {
                    bencher.bench_local_values(|(a, b, c)| {
                        block_multiplier::montgomery_square_interleaved_4(mode_guard, a, b, c)
                    });
                });
            }
        }
    }

    #[divan::bench]
    fn simd_sqr(bencher: Bencher) {
        bencher
            //.counter(ItemsCount::new(2usize))
            .with_inputs(|| rng().random())
            .bench_local_values(|(a, b)| block_multiplier::simd_sqr(a, b));
    }

    #[divan::bench]
    fn block_sqr(bencher: Bencher) {
        let bencher = bencher
            //.counter(ItemsCount::new(3usize))
            .with_inputs(|| rng().random());
        unsafe {
            with_rounding_mode((), |guard, _| {
                bencher.bench_local_values(|(a, b, c)| block_multiplier::block_sqr(guard, a, b, c));
            });
        }
    }
}

fn main() {
    divan::main();
}
