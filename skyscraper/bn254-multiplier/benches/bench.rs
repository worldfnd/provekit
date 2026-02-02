#![feature(portable_simd)]

use {
    divan::Bencher,
    rand::{rng, Rng},
};

// #[divan::bench_group]
mod mul {
    use {super::*, bn254_multiplier::rne};

    #[divan::bench]
    fn scalar_mul(bencher: Bencher) {
        bencher
            //.counter(ItemsCount::new(1usize))
            .with_inputs(|| rng().random())
            .bench_local_values(|(a, b)| bn254_multiplier::scalar_mul(a, b));
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
    fn single_b51(bencher: Bencher) {
        bencher
            //.counter(ItemsCount::new(1usize))
            .with_inputs(|| rng().random())
            .bench_local_values(|(a, b)| rne::single::simd_mul(a, b));
    }

    #[divan::bench]
    fn simd_mul_51b(bencher: Bencher) {
        bencher
            //.counter(ItemsCount::new(2usize))
            .with_inputs(|| rng().random())
            .bench_local_values(|(a, b, c, d)| {
                bn254_multiplier::rne::portable_simd::simd_mul(a, b, c, d)
            });
    }

    #[cfg(target_arch = "aarch64")]
    mod aarch64 {
        use {
            super::*,
            core::{array, simd::u64x2},
            fp_rounding::with_rounding_mode,
        };

        #[divan::bench]
        fn simd_mul_rtz(bencher: Bencher) {
            let bencher = bencher.with_inputs(|| rng().random());
            unsafe {
                with_rounding_mode((), |mode_guard, _| {
                    bencher.bench_local_values(|(a, b, c, d)| {
                        bn254_multiplier::rtz::simd_mul(mode_guard, a, b, c, d)
                    });
                });
            }
        }

        #[divan::bench]
        fn block_mul(bencher: Bencher) {
            let bencher = bencher
                //.counter(ItemsCount::new(3usize))
                .with_inputs(|| rng().random());
            unsafe {
                with_rounding_mode((), |guard, _| {
                    bencher.bench_local_values(|(a, b, c, d, e, f)| {
                        bn254_multiplier::rtz::block_mul(guard, a, b, c, d, e, f)
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
                        bn254_multiplier::montgomery_interleaved_3(mode_guard, a, b, c, d)
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
                        bn254_multiplier::montgomery_interleaved_4(mode_guard, a, b, c, d, e, f)
                    });
                });
            }
        }
    }
}

// #[divan::bench_group]
mod sqr {
    use {super::*, ark_ff::Field, bn254_multiplier::rne};

    #[divan::bench]
    fn scalar_sqr(bencher: Bencher) {
        bencher
            //.counter(ItemsCount::new(1usize))
            .with_inputs(|| rng().random())
            .bench_local_values(bn254_multiplier::scalar_sqr);
    }

    #[divan::bench]
    fn simd_sqr_b51(bencher: Bencher) {
        bencher
            //.counter(ItemsCount::new(1usize))
            .with_inputs(|| rng().random())
            .bench_local_values(|(a, b)| rne::simd_sqr(a, b));
    }

    #[divan::bench]
    fn single_sqr_b51(bencher: Bencher) {
        bencher
            //.counter(ItemsCount::new(1usize))
            .with_inputs(|| rng().random())
            .bench_local_values(|a| rne::single::simd_sqr(a));
    }

    #[divan::bench]
    fn ark_ff(bencher: Bencher) {
        use {ark_bn254::Fr, ark_ff::BigInt};
        bencher
            //.counter(ItemsCount::new(1usize))
            .with_inputs(|| Fr::new(BigInt(rng().random())))
            .bench_local_values(|a: Fr| a.square());
    }

    #[cfg(target_arch = "aarch64")]
    mod aarch64 {
        use {
            super::*,
            core::{array, simd::u64x2},
            fp_rounding::with_rounding_mode,
        };

        #[divan::bench]
        fn montgomery_square_log_interleaved_3(bencher: Bencher) {
            let bencher = bencher.with_inputs(|| {
                (
                    rng().random(),
                    array::from_fn(|_| u64x2::from_array(rng().random())),
                )
            });
            unsafe {
                with_rounding_mode((), |mode_guard, _| {
                    bencher.bench_local_values(|(a, b)| {
                        bn254_multiplier::montgomery_square_log_interleaved_3(mode_guard, a, b)
                    });
                });
            }
        }

        #[divan::bench]
        fn montgomery_square_log_interleaved_4(bencher: Bencher) {
            let bencher = bencher.with_inputs(|| {
                (
                    rng().random(),
                    rng().random(),
                    array::from_fn(|_| u64x2::from_array(rng().random())),
                )
            });
            unsafe {
                with_rounding_mode((), |mode_guard, _| {
                    bencher.bench_local_values(|(a, b, c)| {
                        bn254_multiplier::montgomery_square_log_interleaved_4(mode_guard, a, b, c)
                    });
                });
            }
        }

        #[divan::bench]
        fn montgomery_square_interleaved_3(bencher: Bencher) {
            let bencher = bencher.with_inputs(|| {
                (
                    rng().random(),
                    array::from_fn(|_| u64x2::from_array(rng().random())),
                )
            });
            unsafe {
                with_rounding_mode((), |mode_guard, _| {
                    bencher.bench_local_values(|(a, b)| {
                        bn254_multiplier::montgomery_square_interleaved_3(mode_guard, a, b)
                    });
                });
            }
        }

        #[divan::bench]
        fn montgomery_square_interleaved_4(bencher: Bencher) {
            let bencher = bencher.with_inputs(|| {
                (
                    rng().random(),
                    rng().random(),
                    array::from_fn(|_| u64x2::from_array(rng().random())),
                )
            });
            unsafe {
                with_rounding_mode((), |mode_guard, _| {
                    bencher.bench_local_values(|(a, b, c)| {
                        bn254_multiplier::montgomery_square_interleaved_4(mode_guard, a, b, c)
                    });
                });
            }
        }

        #[divan::bench]
        fn simd_sqr(bencher: Bencher) {
            let bencher = bencher.with_inputs(|| rng().random());
            unsafe {
                with_rounding_mode((), |mode_guard, _| {
                    bencher.bench_local_values(|(a, b)| {
                        bn254_multiplier::rtz::simd_sqr(mode_guard, a, b)
                    });
                });
            }
        }

        #[divan::bench]
        fn block_sqr(bencher: Bencher) {
            let bencher = bencher
                //.counter(ItemsCount::new(3usize))
                .with_inputs(|| rng().random());
            unsafe {
                with_rounding_mode((), |guard, _| {
                    bencher.bench_local_values(|(a, b, c)| {
                        bn254_multiplier::rtz::block_sqr(guard, a, b, c)
                    });
                });
            }
        }
    }
}

fn main() {
    divan::main();
}
