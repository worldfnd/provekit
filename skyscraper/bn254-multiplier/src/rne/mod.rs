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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod output_bound_tests {
    use {
        super::mono,
        crate::constants::U64_P_MULTIPLES,
        proptest::{prelude::*, test_runner::Config},
    };

    fn le256(a: [u64; 4], b: [u64; 4]) -> bool {
        for i in (0..4).rev() {
            if a[i] != b[i] {
                return a[i] < b[i];
            }
        }
        true
    }

    fn below_2_255() -> impl Strategy<Value = [u64; 4]> {
        (0u64.., 0u64.., 0u64.., 0u64..(1u64 << 63)).prop_map(|(a, b, c, d)| [a, b, c, d])
    }

    proptest! {
        #![proptest_config(Config { cases: 4096, .. Config::default() })]
        #[test]
        fn mono_mul_output_under_3p(a in below_2_255(), b in below_2_255()) {
            let out = mono::mul(a, b);
            prop_assert!(le256(out, U64_P_MULTIPLES[3]),
                "mul({:?}, {:?}) = {:?} ≥ 3p", a, b, out);
        }
    }
}
