use {
    core::hint::black_box,
    divan::{counter::ItemsCount, Bencher},
    fp_rounding::with_rounding_mode,
    rand::{rng, Rng},
    std::array,
};

#[divan::bench_group]
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

#[divan::bench]
fn reference(bencher: Bencher) {
    let mut rng = rng();
    let a = array::from_fn(|_| rng.random());
    let b = array::from_fn(|_| rng.random());
    bencher
        .counter(ItemsCount::new(1_usize))
        .bench_local(|| skyscraper::reference::compress(black_box(a), black_box(b)))
}

#[divan::bench]
fn compress_many_ref(bencher: Bencher) {
    let size = 1000_usize;
    let mut rng = rng();
    let messages: Vec<u8> = (0..(size * 64)).map(|_| rng.random()).collect();
    let mut hashes = vec![0_u8; size * 32];
    bencher.counter(ItemsCount::new(size)).bench_local(|| {
        skyscraper::reference::compress_many(black_box(&messages), black_box(&mut hashes));
    });
}

#[divan::bench]
fn compress_many_scalar(bencher: Bencher) {
    let size = 1000_usize;
    let mut rng = rng();
    let messages: Vec<u8> = (0..(size * 64)).map(|_| rng.random()).collect();
    let mut hashes = vec![0_u8; size * 32];
    bencher.counter(ItemsCount::new(size)).bench_local(|| {
        skyscraper::simple::compress_many(black_box(&messages), black_box(&mut hashes));
    });
}

#[divan::bench]
fn block_compress(bencher: Bencher) {
    let mut rng = rng();
    let a = array::from_fn(|_| rng.random());
    let b = array::from_fn(|_| rng.random());
    let c = array::from_fn(|_| rng.random());
    let d = array::from_fn(|_| rng.random());
    let e = array::from_fn(|_| rng.random());
    let f = array::from_fn(|_| rng.random());
    unsafe {
        with_rounding_mode((), |guard, _| {
            bencher.counter(ItemsCount::new(3_usize)).bench_local(|| {
                skyscraper::block::block_compress(
                    guard,
                    black_box(a),
                    black_box(b),
                    black_box(c),
                    black_box(d),
                    black_box(e),
                    black_box(f),
                )
            })
        });
    }
}

fn main() {
    divan::main();
}
