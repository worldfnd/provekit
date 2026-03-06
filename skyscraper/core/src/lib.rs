#![feature(portable_simd)]
#![feature(const_unsigned_bigint_helpers)]

pub mod arithmetic;
pub mod bar;
#[cfg(target_arch = "aarch64")]
pub mod block3;
#[cfg(target_arch = "aarch64")]
pub mod block4;
pub mod constants;
pub mod generic;
pub mod pow;
pub mod reduce;
pub mod reference;
pub mod simple;
pub mod v1;

/// The least common multiple of the implementation widths.
///
/// Doing this many compressions in parallel will make optimal use of resources
/// in all implementations.
///
/// Note you might want to pick a multiple as block size to amortize the setting
/// of rounding mode.
pub const WIDTH_LCM: usize = 12;

pub type CompressManyFn = fn(&[u8], &mut [u8]);

/// Platform-optimal batched compression (block4 on aarch64, simple elsewhere).
#[cfg(target_arch = "aarch64")]
pub use block4::compress_many;
#[cfg(not(target_arch = "aarch64"))]
pub use simple::compress_many;

// TODO: Some autotune method that does a small benchmark on target hardware and
// finds the optimal implementation. It should also have an enum that can be
// stored in a file. And the benchmarking should be instrumented.
