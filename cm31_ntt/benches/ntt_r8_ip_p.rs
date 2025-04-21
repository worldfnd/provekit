use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use cm31_ntt::ntt_utils::get_root_of_unity;
use cm31_ntt::ntt::*;
use cm31_ntt::cm31::CF;
use num_traits::Zero;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_r8_ip_p");

    for log8_n in 7..9 {
        let n = 8usize.pow(log8_n);
        let wn = get_root_of_unity(n as usize);

        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let mut f = vec![CF::zero(); n];
        for i in 0..n {
            f[i] = rng.r#gen();
        }

        let precomp = precomp_for_ntt_r8_ip_p(n, wn);

        let mut scratch = vec![CF::zero(); n];

        group.bench_function(format!("size {n}"), |b| {
            b.iter(|| {
                ntt_r8_ip_p(black_box(&mut f), &mut scratch, &precomp);
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

