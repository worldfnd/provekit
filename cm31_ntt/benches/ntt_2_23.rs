use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use cm31_ntt::ntt_utils::{get_root_of_unity, precompute_twiddles, precompute_twiddles_stride4};
use cm31_ntt::ntt::{ntt_8_stride_4, ntt_8_stride_4_precomputed};
use cm31_ntt::cm31::CF;
use num_traits::Zero;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

fn bench_2_23(c: &mut Criterion) {
    let radix = 8;

    // 2^23 = 8,388,608 elements
    let n = 1 << 23;
    let quarter_n = n / 4; // quarter size for radix-8 part

    // Get the primitive root of unity for the quarter-size and precompute twiddle factors
    let w_quarter = get_root_of_unity(quarter_n);
    
    // Precompute twiddle factors for radix-8 NTTs on quarter the input size
    let r8_twiddles = precompute_twiddles(quarter_n, w_quarter, radix);
    
    // Precompute twiddle factors for stride-4 combination stage
    let stride4_twiddles = precompute_twiddles_stride4(n);

    let mut group = c.benchmark_group("NTT (2^23) with stride-4");

    let mut rng = ChaCha8Rng::seed_from_u64(0);

    let mut f = vec![CF::zero(); n];
    for i in 0..n {
        f[i] = rng.r#gen();
    }

    group.bench_function(format!("size {n} without precomputation"), |b| {
        b.iter(|| {
            let f_clone = f.clone();
            ntt_8_stride_4(black_box(f_clone));
        })
    });
    
    group.bench_function(format!("size {n} with precomputation"), |b| {
        b.iter(|| {
            let f_clone = f.clone();
            ntt_8_stride_4_precomputed(black_box(f_clone), &r8_twiddles, &stride4_twiddles);
        })
    });
    
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_2_23
}
criterion_main!(benches);
