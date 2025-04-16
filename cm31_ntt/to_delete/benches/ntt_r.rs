use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use cm31_ntt::ntt_utils::{get_root_of_unity, precompute_twiddles};
use cm31_ntt::cm31::CF;
use cm31_ntt::ntt_r::*;
use num_traits::Zero;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

fn bench(c: &mut Criterion) {
    let radix = 8;
    let mut group = c.benchmark_group("NTT radix-64");
    let w_64 = get_root_of_unity(64);

    for n in [512] {
        let w = get_root_of_unity(n as usize);

        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let mut arr = vec![CF::zero(); n];
        for i in 0..n {
            arr[i] = rng.r#gen();
        }

        group.bench_function(format!("ntt_mixed_8x64"), |b| {
            b.iter(|| {
                ntt_mixed_8x64(black_box(&mut arr), w);
            })
        });
    }

    //for n in [64, 4096, 262144, 16777216] {
        //let w = get_root_of_unity(n as usize);
        //let twiddles = precompute_twiddles(n as usize, w, radix);

        //let mut rng = ChaCha8Rng::seed_from_u64(0);

        //let mut arr = vec![CF::zero(); n];
        //for i in 0..n {
            //arr[i] = rng.r#gen();
        //}

        //group.bench_function(format!("size {n} without precomputation"), |b| {
            //b.iter(|| {
                //ntt_radix_r(black_box(arr.clone()), 64, w, w_64);
            //})
        //});
    //}
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
}
criterion_main!(benches);
