#![feature(portable_simd)]
#![feature(bigint_helper_methods)]
//#![no_std] This crate can technically be no_std. This requires replacing the
// use StdFloat.mul_add as this has a fallback which on our supported
// target platforms is not needed.

#[cfg(target_arch = "aarch64")]
mod aarch64;

// These can be made to work on x86,
// but for now it uses an ARM NEON intrinsic.
#[cfg(target_arch = "aarch64")]
mod block_simd;
#[cfg(target_arch = "aarch64")]
mod portable_simd;
#[cfg(target_arch = "aarch64")]
mod simd_utils;

pub mod constants;
mod scalar;
mod test_utils;
mod utils;

pub use crate::scalar::{scalar_mul, scalar_sqr};
#[cfg(target_arch = "aarch64")]
pub use crate::{
    aarch64::{
        montgomery_interleaved_3, montgomery_interleaved_4, montgomery_square_interleaved_3,
        montgomery_square_interleaved_4, montgomery_square_log_interleaved_3,
        montgomery_square_log_interleaved_4,
    },
    block_simd::{block_mul, block_sqr},
    portable_simd::{simd_mul, simd_sqr},
};
