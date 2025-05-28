#![feature(portable_simd)]
#![feature(bigint_helper_methods)]

mod aarch64;
mod block_simd;
pub mod constants;
mod portable_simd;
mod scalar;
mod utils;

pub use crate::{
    aarch64::{
        montgomery_interleaved_3, montgomery_interleaved_4, montgomery_square_interleaved_3,
    },
    block_simd::{block_mul, block_sqr},
    portable_simd::{simd_mul, simd_sqr},
    scalar::{scalar_mul, scalar_sqr},
};
