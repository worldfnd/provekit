#![feature(portable_simd)]
#![feature(bigint_helper_methods)]
//#![no_std] This crate can technically be no_std. However this requires
// replacing StdFloat.mul_add with intrinsics.

#[cfg(target_arch = "aarch64")]
mod aarch64;

// These can be made to work on x86,
// but for now it uses an ARM NEON intrinsic.
#[cfg(target_arch = "aarch64")]
pub mod rtz;

pub mod constants;
pub mod rne;
mod scalar;
mod utils;

#[cfg(not(target_arch = "wasm32"))] // Proptest not supported on WASI
mod test_utils;

#[cfg(target_arch = "aarch64")]
pub use crate::aarch64::{
    montgomery_interleaved_3, montgomery_interleaved_4, montgomery_square_interleaved_3,
    montgomery_square_interleaved_4, montgomery_square_log_interleaved_3,
    montgomery_square_log_interleaved_4,
};
pub use crate::scalar::{scalar_mul, scalar_sqr};

const fn pow_2(n: u32) -> f64 {
    assert!(n <= 1023);
    // Unfortunately we can't use f64::powi in const fn yet
    // This is a workaround that creates the bit pattern directly
    let exp = (n as u64 + 1023) << 52;
    f64::from_bits(exp)
}
