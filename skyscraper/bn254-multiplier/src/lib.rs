#![cfg_attr(not(kani), feature(portable_simd))]
//#![no_std] This crate can technically be no_std. However this requires
// replacing StdFloat.mul_add with intrinsics.

#[cfg(all(target_arch = "aarch64", not(kani)))]
mod aarch64;

// These can be made to work on x86,
// but for now it uses an ARM NEON intrinsic.
#[cfg(all(target_arch = "aarch64", not(kani)))]
pub mod rtz;

pub mod constants;
#[cfg(not(kani))]
pub mod rne;
#[cfg(not(kani))]
mod scalar;
pub mod utils;

#[cfg(all(not(target_arch = "wasm32"), not(kani)))]
mod test_utils;

#[cfg(all(target_arch = "aarch64", not(kani)))]
pub use crate::aarch64::{
    montgomery_interleaved_3, montgomery_interleaved_4, montgomery_square_interleaved_3,
    montgomery_square_interleaved_4, montgomery_square_log_interleaved_3,
    montgomery_square_log_interleaved_4,
};
#[cfg(not(kani))]
pub use crate::scalar::{scalar_mul, scalar_sqr};

const fn pow_2(n: u32) -> f64 {
    assert!(n <= 1023);
    // Unfortunately we can't use f64::powi in const fn yet
    // This is a workaround that creates the bit pattern directly
    let exp = (n as u64 + 1023) << 52;
    f64::from_bits(exp)
}
