use {
    ark_bn254::Fr,
    ark_ff::Field,
    core::hint::black_box,
    divan::{counter::ItemsCount, Bencher},
    fp_rounding::with_rounding_mode,
    rand::{rng, Rng},
    std::array,
};

#[divan::bench]
fn reference(bencher: Bencher) {
    let mut rng = rng();
    let a = Fr::from_random_bytes(&rng.random::<[u8; 32]>()).unwrap();
    let b = Fr::from_random_bytes(&rng.random::<[u8; 32]>()).unwrap();
    bencher
        .counter(ItemsCount::new(1_usize))
        .bench_local(|| skyscraper::compress_ref(black_box(a), black_box(b)))
}

#[divan::bench]
fn compress(bencher: Bencher) {
    let mut rng = rng();
    let a = array::from_fn(|_| rng.random());
    let b = array::from_fn(|_| rng.random());
    bencher
        .counter(ItemsCount::new(1_usize))
        .bench_local(|| skyscraper::compress(black_box(a), black_box(b)))
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
                skyscraper::block_compress(
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
