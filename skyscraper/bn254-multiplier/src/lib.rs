#![feature(portable_simd)]
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

/// Precomputed magic constants for fast approximate floor division by the
/// BN254 prime P, following Warren's "Hacker's Delight" (integer division by
/// constants). Guarantees `div_p(val) ≤ ⌊val / P⌋` for all inputs within the
/// declared bit range.
pub struct MulShift {
    mul:   u64,
    shift: u32,
}

impl MulShift {
    /// Computes magic multiplication and shift constants for approximate floor
    /// division by P, such that `div_p(val) ≤ ⌊val / P⌋` for all `val` within
    /// `max_bit_size` bits. `precision` controls how many of the top bits of
    /// `val` are used — higher precision yields a tighter approximation.
    pub const fn new(max_bit_size: u32, precision: u32) -> Self {
        // Generate magic numbers for division by bn254's prime for a range of top-bit
        // widths.

        // Based on Warren's "Hacker's Delight" (integer
        // division by constants) to find a magic multiplier for each bit-width.

        // Returns a list of tuples (w, m_bits, sub, shift, m) where:
        //- w: number of top bits of the value
        //- m_bits: number of bits in the magic multiplier
        //- sub: whether the "subtract and shift" variant is used (m exceeded 2^w,
        //  so we store m - 2^w and compensate at runtime)
        //- shift: the number of bits to right-shift the product (called 's' in Warren)
        //- m: the magic multiplier
        use crate::constants::U64_P;

        let d = (U64_P[3] >> (max_bit_size - 192 - precision)) + 1; // d = divisor = ceil(p / 2^(max_bit_size-w))
        let nc = 2_u64.pow(precision) - 1 - (2_u64.pow(precision) % d); // nc = largest value s.t. nc mod d == d-1
        let mut s = precision; // start at precision; s < precision values are skipped
        let m;
        loop {
            // s = shift exponent
            if 2_u64.pow(s) > nc * (d - 1 - (2_u64.pow(s) - 1) % d) {
                m = (2_u64.pow(s) + d - 1 - (2_u64.pow(s) - 1) % d) / d; // m = magic multiplier
                break;
            }
            s += 1;
            assert!(s < 64, "no magic multiplier found");
        }

        MulShift { mul: m, shift: s }
    }

    #[inline(always)]
    /// Returns an under-approximation of ⌊val / P⌋ (result ≤ true quotient).
    /// `val` must fit within the `max_bit_size` passed to [`MulShift::new`].
    pub const fn div_p(&self, val: u64) -> u64 {
        // assumes systems can handle multiplication by 64 bits without performance
        // penalty.
        (val * self.mul) >> self.shift
    }
}

/// Approximate floor division by P using the upper 6 bits of `x`.
/// `x` must be the upper limb of a u256 in 64-bit radix.
///
/// Returns a value ≤ ⌊x / P⌋. This is the most precise
/// approximation achievable without multiplication on ARM64 and x86.
///
/// Tradeoff: due the limited range of this division [0,4] (instead of [0,5] for
/// u256) will to a larger value after subtraction reduction.
/// subtraction reduction output: [0, 1+ε] with ε < 0.3.
pub fn div_p_6b(x: u64) -> u64 {
    let upper_bits = x >> (64 - 6);
    // const to force compile time evaluation
    const MULSHIFT: MulShift = MulShift::new(256, 6);
    MULSHIFT.div_p(upper_bits)
}

/// Approximate floor division by P using the upper 32 bits of `x`.
/// `x` must be the upper limb of a u256 in 64-bit radix.
///
/// Returns a value ≤ ⌊x / P⌋. This is the most precise
/// approximation achievable with a 32bx32b->64b multiplier.
pub fn div_p_32b(x: u64) -> u64 {
    let upper_bits = x >> (64 - 32);
    // const to force compile time evaluation
    const MULSHIFT: MulShift = MulShift::new(256, 32);
    MULSHIFT.div_p(upper_bits)
}

#[cfg(kani)]
mod proofs {
    use {
        super::{
            constants::{U64_2P, U64_P},
            div_p_32b, div_p_6b, MulShift,
        },
        crate::constants::U64_P_MULTIPLES,
    };

    /// Compute q * P as (4-limb little-endian result, overflow carry).
    fn mul_small_by_p(q: u64) -> ([u64; 4], u64) {
        let q = q as u128;
        let t0 = q * U64_P[0] as u128;
        let t1 = q * U64_P[1] as u128 + (t0 >> 64);
        let t2 = q * U64_P[2] as u128 + (t1 >> 64);
        let t3 = q * U64_P[3] as u128 + (t2 >> 64);
        (
            [t0 as u64, t1 as u64, t2 as u64, t3 as u64],
            (t3 >> 64) as u64,
        )
    }

    /// Lexicographic ≤ on little-endian 256-bit integers.
    fn le256(a: [u64; 4], b: [u64; 4]) -> bool {
        for i in (0..4).rev() {
            if a[i] != b[i] {
                return a[i] < b[i];
            }
        }
        true
    }

    /// For every 64-bit x, div_p_32b(x) * P ≤ x * 2^192.
    /// TODO: encode tighter bounds
    #[kani::proof]
    fn div_p_32b_underapprox() {
        let x: u64 = kani::any();
        let q = div_p_32b(x);

        let r = U64_P_MULTIPLES[q as usize][3];
        assert!(le256([0, 0, 0, x - r], U64_2P));
    }

    #[kani::proof]
    // TODO tighter bounds
    fn div_p_6b_underapprox() {
        let x: u64 = kani::any();
        let q = div_p_6b(x);

        let r = U64_P_MULTIPLES[q as usize][3];
        assert!(le256([0, 0, 0, x - r], U64_2P));
    }
}
