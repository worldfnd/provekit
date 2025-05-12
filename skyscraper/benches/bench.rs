use {
    core::hint::black_box,
    divan::Bencher,
    rand::{rng, Rng},
    std::array,
};

// #[divan::bench_group]
mod reduce {
    use super::*;

    #[divan::bench]
    fn reduce_1_partial(bencher: Bencher) {
        use skyscraper::reduce::reduce_partial;
        bencher
            .with_inputs(|| reduce_partial(array::from_fn(|_| rng().random())))
            .bench_values(skyscraper::reduce::reduce_1)
    }

    #[divan::bench]
    fn reduce_1(bencher: Bencher) {
        bencher
            .with_inputs(|| array::from_fn(|_| rng().random()))
            .bench_values(skyscraper::reduce::reduce_1)
    }

    #[divan::bench]
    fn reduce_partial(bencher: Bencher) {
        bencher
            .with_inputs(|| array::from_fn(|_| rng().random()))
            .bench_values(skyscraper::reduce::reduce_partial)
    }

    #[divan::bench]
    fn reduce(bencher: Bencher) {
        bencher
            .with_inputs(|| array::from_fn(|_| rng().random()))
            .bench_values(skyscraper::reduce::reduce)
    }

    #[divan::bench]
    fn reduce_add_rc(bencher: Bencher) {
        bencher
            .with_inputs(|| {
                (
                    array::from_fn(|_| rng().random()),
                    rng().random_range(0..18),
                )
            })
            .bench_values(|(x, rc)| skyscraper::reduce::reduce_partial_add_rc(x, rc))
    }
}

// #[divan::bench_group]
mod pow {
    use {super::*, skyscraper::pow::solve};

    #[divan::bench]
    fn bits_05(bencher: Bencher) {
        bencher
            .with_inputs(|| rng().random())
            .bench_local_values(|challenge| solve(challenge, 05.0))
    }

    #[divan::bench]
    fn bits_10(bencher: Bencher) {
        bencher
            .with_inputs(|| rng().random())
            .bench_local_values(|challenge| solve(challenge, 10.0))
    }

    #[divan::bench]
    fn bits_15(bencher: Bencher) {
        bencher
            .with_inputs(|| rng().random())
            .bench_local_values(|challenge| solve(challenge, 15.0))
    }

    #[divan::bench]
    fn bits_20(bencher: Bencher) {
        bencher
            .with_inputs(|| rng().random())
            .bench_local_values(|challenge| solve(challenge, 20.0))
    }

    #[divan::bench]
    #[ignore]
    fn bits_25(bencher: Bencher) {
        bencher
            .with_inputs(|| rng().random())
            .bench_local_values(|challenge| solve(challenge, 25.0))
    }
}

// #[divan::bench_group]
mod compress_many {
    use super::*;

    const SIZE: usize = 256;

    #[divan::bench]
    fn reference(bencher: Bencher) {
        let mut rng = rng();
        let messages: Vec<u8> = (0..(SIZE * 64)).map(|_| rng.random()).collect();
        let mut hashes = vec![0_u8; SIZE * 32];
        bencher
            //.counter(ItemsCount::new(SIZE))
            .bench_local(|| {
                skyscraper::reference::compress_many(black_box(&messages), black_box(&mut hashes));
            });
    }

    #[divan::bench]
    fn simple(bencher: Bencher) {
        let mut rng = rng();
        let messages: Vec<u8> = (0..(SIZE * 64)).map(|_| rng.random()).collect();
        let mut hashes = vec![0_u8; SIZE * 32];
        bencher
            //.counter(ItemsCount::new(SIZE))
            .bench_local(|| {
                skyscraper::simple::compress_many(black_box(&messages), black_box(&mut hashes));
            });
    }

    #[divan::bench]
    fn block3(bencher: Bencher) {
        bencher
            //.counter(ItemsCount::new(SIZE))
            .with_inputs(|| {
                (
                    (0..(SIZE * 64))
                        .map(|_| rng().random())
                        .collect::<Vec<u8>>(),
                    vec![0_u8; SIZE * 32],
                )
            })
            .bench_local_refs(|(messages, hashes)| {
                skyscraper::block3::compress_many(messages, hashes);
            });
    }

    #[divan::bench]
    fn block4(bencher: Bencher) {
        bencher
            //.counter(ItemsCount::new(SIZE))
            .with_inputs(|| {
                (
                    (0..(SIZE * 64))
                        .map(|_| rng().random())
                        .collect::<Vec<u8>>(),
                    vec![0_u8; SIZE * 32],
                )
            })
            .bench_local_refs(|(messages, hashes)| {
                skyscraper::block4::compress_many(messages, hashes);
            });
    }

    #[divan::bench]
    fn v1(bencher: Bencher) {
        let mut rng = rng();
        let messages: Vec<u8> = (0..(SIZE * 64)).map(|_| rng.random()).collect();
        let mut hashes = vec![0_u8; SIZE * 32];
        bencher
            //.counter(ItemsCount::new(SIZE))
            .bench_local(|| {
                skyscraper::v1::compress_many(black_box(&messages), black_box(&mut hashes));
            });
    }
}

// #[divan::bench_group]
mod parts {
    use super::*;

    #[divan::bench]
    fn bar(bencher: Bencher) {
        use skyscraper::reduce::reduce_partial;
        bencher
            .with_inputs(|| reduce_partial(array::from_fn(|_| rng().random())))
            .bench_values(skyscraper::bar::bar)
    }

    #[divan::bench]
    fn sbox(bencher: Bencher) {
        bencher
            .with_inputs(|| rng().random())
            .bench_values(skyscraper::bar::sbox)
    }

    #[divan::bench]
    fn sbox_8(bencher: Bencher) {
        bencher
            .with_inputs(|| rng().random())
            .bench_values(skyscraper::bar::sbox_8)
    }

    #[divan::bench]
    fn sbox_16(bencher: Bencher) {
        bencher
            .with_inputs(|| rng().random())
            .bench_values(skyscraper::bar::sbox_16)
    }

    #[divan::bench]
    fn square(bencher: Bencher) {
        use skyscraper::reduce::reduce_partial;
        bencher
            .with_inputs(|| reduce_partial(array::from_fn(|_| rng().random())))
            .bench_values(block_multiplier::scalar_sqr)
    }
}

fn main() {
    divan::main();
}
