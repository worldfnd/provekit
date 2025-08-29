use {
    cm31_ntt::{cm31::CF, ntt::*, ntt_utils::get_root_of_unity},
    criterion::{Criterion, criterion_group, criterion_main},
    lazy_static::lazy_static,
    num_traits::Zero,
    rand::Rng,
    rand_chacha::{ChaCha8Rng, rand_core::SeedableRng},
    std::hint::black_box,
};

lazy_static! {
    static ref PRECOMP: Vec<CF> = {
        let n = 8usize.pow(8);
        let wn = get_root_of_unity(n);
        precomp_for_ntt_r8_vec_p(n, wn).unwrap()
    };
}
fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_r8_vec_p");

    for log8_n in 7..9 {
        let n = 8usize.pow(log8_n);
        // let wn = get_root_of_unity(n as usize);
        // let precomp = precomp_vec_twiddles(n, wn);
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let mut f = vec![CF::zero(); n];
        for i in 0..n {
            f[i] = rng.r#gen();
        }

        group.bench_function(format!("size {n}"), |b| {
            b.iter(|| {
                let _ = ntt_r8_vec_p(black_box(&f), &*PRECOMP);
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
