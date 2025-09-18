use divan;
/// Benchmarks for NTTEngine with divan
use ntt::NTTEngine;

fn main() {
    // Initialize Rayon thread pool
    rayon::ThreadPoolBuilder::new().build_global().unwrap();

    divan::main();
}

/// Benchmark group for NTTEngine with order 1<<24
// #[divan::bench_group(sample_count = 5)]
// mod ntt_engine_1_24 {
use ntt::Pow2OrZero;

const ORDER: usize = 1 << 24; // 2^24 = 16,777,216

/// Benchmark NTTEngine creation with order 1<<24
#[divan::bench]
fn create_engine() {
    let _engine = divan::black_box(NTTEngine::new(Pow2OrZero::new(ORDER).unwrap()));
}
// }
