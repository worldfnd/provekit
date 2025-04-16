use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use cm31_ntt::ntt_utils::get_root_of_unity;
use cm31_ntt::ntt::*;
use cm31_ntt::cm31::CF;
use num_traits::Zero;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

use lazy_static::lazy_static;

lazy_static! {
    static ref PRECOMP: Vec<CF> = {
        let n = 8usize.pow(8);
        let wn = get_root_of_unity(n);
        precomp_vec_twiddles(n, wn, 8)
    };
}
fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt::ntt_radix_8");

    for log8_n in [8] {
        let n = 8usize.pow(log8_n);
        //let wn = get_root_of_unity(n as usize);
        //let precomp = precomp_vec_twiddles(n, wn, 8);
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let mut f = vec![CF::zero(); n];
        for i in 0..n {
            f[i] = rng.r#gen();
        }

        group.bench_function(format!("size {n} with precomputation (Vec)"), |b| {
            b.iter(|| {
                ntt_radix_8_precomp(black_box(&f), &*PRECOMP);
            })
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
}
criterion_main!(benches);

