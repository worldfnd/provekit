use divan;
/// Benchmarks for NTTEngine with divan
use ntt::NTTEngine;

fn main() {
    // Initialize Rayon thread pool
    rayon::ThreadPoolBuilder::new().build_global().unwrap();

    divan::main();
}

use ntt::Pow2OrZero;

const ORDER: usize = 1 << 24;

/// Benchmark NTTEngine creation with order 1<<24
#[divan::bench]
fn create_engine() {
    let _engine = divan::black_box(NTTEngine::with_order(Pow2OrZero::new(ORDER).unwrap()));
}
