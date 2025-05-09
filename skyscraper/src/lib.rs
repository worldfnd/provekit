#![feature(portable_simd)]
#![feature(bigint_helper_methods)]
#![feature(cold_path)]

pub mod arithmetic;
pub mod autotune;
pub mod bar;
pub mod block;
pub mod block3;
pub mod block4;
pub mod constants;
pub mod reduce;
pub mod reference;
pub mod simple;
pub mod v1;

pub type CompressManyFn = fn(&[u8], &mut [u8]);

// TODO: Some autotune method that does a small benchmark on target hardware and
// finds the optimal implementation. It should also have an enum that can be
// stored in a file. And the benchmarking should be instrumented.
