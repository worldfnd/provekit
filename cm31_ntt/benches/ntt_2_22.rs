use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use cm31_ntt::ntt_utils::{get_root_of_unity, precompute_twiddles, precompute_twiddles_stride2};
use cm31_ntt::ntt::{ntt_8_stride_2, ntt_8_stride_2_precomputed};
use cm31_ntt::cm31::CF;
use num_traits::Zero;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

fn bench_2_22(c: &mut Criterion) {
    let radix = 8;

    // 2^22 = 4,194,304 elements
    let n = 1 << 22;
    let half_n = n / 2; // half size for radix-8 part

    // Get the primitive root of unity for the half-size and precompute twiddle factors
    let w_half = get_root_of_unity(half_n);
    
    // Precompute twiddle factors for radix-8 NTTs on half the input size
    let r8_twiddles = precompute_twiddles(half_n, w_half, radix);
    
    // Precompute twiddle factors for stride-2 combination stage
    let stride2_twiddles = precompute_twiddles_stride2(n);

    let mut group = c.benchmark_group("NTT (2^22) with stride-2");

    let mut rng = ChaCha8Rng::seed_from_u64(0);

    let mut f = vec![CF::zero(); n];
    for i in 0..n {
        f[i] = rng.r#gen();
    }

    group.bench_function(format!("size {n} without precomputation"), |b| {
        b.iter(|| {
            let f_clone = f.clone();
            ntt_8_stride_2(black_box(f_clone));
        })
    });
    
    group.bench_function(format!("size {n} with precomputation"), |b| {
        b.iter(|| {
            let f_clone = f.clone();
            ntt_8_stride_2_precomputed(black_box(f_clone), &r8_twiddles, &stride2_twiddles);
        })
    });
    
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_2_22
}
criterion_main!(benches);
