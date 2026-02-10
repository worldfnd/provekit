//! # RNE - Round-to-Nearest-Even Montgomery Multiplication
//!
//! This module implements Montgomery multiplication over the BN254 scalar field
//! using floating-point arithmetic with round-to-nearest-even (RNE) rounding
//! mode.
//!
//! ## Why Floating-Point?
//!
//! On WASM and ARM Cortex, integer multiplication has lower throughput
//! than floating-point FMA (fused multiply-add). By encoding
//! 51-bit limbs into the mantissa of f64 values we can perform integer
//! multiplication using FMA.
//!
//! ## Representation
//!
//! Field elements are stored in a 5-limb redundant form with 51 bits per limb
//! (5 × 51 = 255 bits), allowing representation of values up to 2²⁵⁵ - 1.
//!
//! ## References
//!
//! Variation of "Faster Modular Exponentiation using Double Precision Floating
//! Point Arithmetic on the GPU, 2018 IEEE 25th Symposium on Computer Arithmetic
//! (ARITH) by Emmart, Zheng and Weems; which uses RTZ.

pub mod batched;
pub mod constants;
pub mod mono;
pub mod simd_utils;

pub use {batched::*, constants::*, mono::*};
