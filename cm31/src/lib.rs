//! Arithmetic over the Mersenne prime p = 2^31 - 1 (“M31”).
//!
//! This module provides fast, allocation-free helpers to work with values that
//! are intended to live in the finite field modulo \(2^{31}-1\). It relies on:
//! - a 62-bit signed accumulator representation (`i62` stored in `i64`) for
//!   intermediate results on 64-bit machines, and
//! - reductions that add the high 31-bit chunk into the low 31-bit chunk until
//!   the result fits within the desired bits.
//!
//! Safety: When modifying this file, rerun with Kani
use std::ops::{Add, Mul, Shl, Sub};

/// Newtype wrapper for values participating in arithmetic modulo 2^31 - 1.
///
/// The generic parameter models the “shape” of the wrapped value:
/// - `u32`: a value known to fit in 32 bits. Primarily used for storage and to
///   tighten bounds when reasoning about sizes.
/// - `i64`: a 62-bit signed accumulator (stored in `i64`). This representation
///   is used for intermediate results.
///
/// In general, operations widen into the accumulator form and should be
/// followed by an explicit reduction when a canonical representative is
/// required.
#[derive(Copy, Clone)]
pub struct M31<T>(T);

/// Trait for types that can be reduced modulo \(2^{31}-1\).
trait M31Reduce {
    /// Partially reduces the value so it fits in 32 bits. This is typically one
    /// reduction round for Mersenne moduli.
    fn reduce_u32(self) -> M31<u32>;
    /// Fully reduces into the canonical representative in 0..(2^31 - 1).
    /// Typically requires two reduction rounds
    fn reduce_fully(self) -> u32;
}

impl<T: M31Reduce> M31Reduce for M31<T> {
    fn reduce_u32(self) -> M31<u32> {
        self.0.reduce_u32()
    }

    fn reduce_fully(self) -> u32 {
        self.0.reduce_fully()
    }
}

/// All operations assume that `i64` values are valid `i62`. No separate newtype
/// is introduced to keep boilerplate to a minimum. Callers must ensure signed
/// intermediate results stay within 62 bits.
///
/// Intuitively, the upper three bits act as a sign extension; they must not
/// disagree with each other. This enables an efficient `i62` representation on
/// 64-bit machines.
///
/// 62 bits has been chosen over 64 bits as 64 bits would necessitate another
/// round of reduction while most algorithms do not require that much space.
impl M31Reduce for i64 {
    #[inline(always)]
    fn reduce_u32(self) -> M31<u32> {
        let reduced = reduce_round(one_complement(self)) as u32;
        M31(reduced)
    }

    #[inline(always)]
    fn reduce_fully(self) -> u32 {
        // Two rounds to fully reduce down
        let tmp = self.reduce_u32().0;
        let tmp = (tmp >> 31) + (tmp & ((1 << 31) - 1));
        // branch should become CSEL
        if tmp == ((1 << 31) - 1) {
            0
        } else {
            tmp
        }
    }
}

/// `u32` is the preferred storage type.
///
/// On 64-bit machines, the computational benefit comes from using `i64`
/// accumulators and reducing operands to 32 bits before multiplication so
/// that only a single 64-bit multiplication is required.
impl M31Reduce for u32 {
    #[inline(always)]
    fn reduce_u32(self) -> M31<u32> {
        M31(self)
    }

    #[inline(always)]
    fn reduce_fully(self) -> u32 {
        let tmp = self;
        let tmp = (tmp >> 31) + (tmp & ((1 << 31) - 1));
        let tmp = (tmp >> 31) + (tmp & ((1 << 31) - 1));
        // branch should become CSEL
        if tmp == ((1 << 31) - 1) {
            0
        } else {
            tmp
        }
    }
}

/// Performs a single reduction round.
/// The caller is responsible for invoking a sufficient number of
/// rounds to reach the desired bound.
#[inline(always)]
fn reduce_round(r: u64) -> i64 {
    let lo = r & ((1 << 31) - 1);
    let hi = r >> 31;
    (hi + lo) as i64
}

/// Converts an `i62` accumulator into its ones’ complement `u62` form.
///
/// By taking the ones’ complement we leverage the correspondence between ones’
/// complement and arithmetic modulo Mersenne numbers. Equivalently, this maps a
/// signed 62-bit value to an unsigned 62-bit number while preserving the
/// residue class modulo \(2^{31}-1\).
fn one_complement(r: i64) -> u64 {
    // Relies on the arithmetic shift right to extend the three sign bits to an
    // i64.
    let sign = r >> 61;
    // Use the sign information to turn into one complement and clear out the
    // redundant sign bits as these would lead to an overcorrection.
    ((r + sign) & ((1 << 62) - 1)) as u64
}

// The following traits reduce the boiler plate when working with M31 by taking
// on some of the widening and reducing required.

/// Multiplication in M31 arithmetic.
///
/// Operands are first reduced to 32 bits, multiplied, and then folded
/// once, yielding an 34 bit result.
impl<T: M31Reduce, K: M31Reduce> Mul<M31<T>> for M31<K> {
    type Output = M31<i64>;

    #[inline(always)]
    fn mul(self, rhs: M31<T>) -> Self::Output {
        let lhs = self.0.reduce_u32();
        let rhs = rhs.0.reduce_u32();
        let res = lhs.0 as u64 * rhs.0 as u64;
        // After reduction 34 bits
        M31(reduce_round(res))
    }
}

/// Subtraction in M31 arithmetic. Widens into a `i62`.
impl<T: Into<i64>, K: Into<i64>> Sub<M31<T>> for M31<K> {
    type Output = M31<i64>;

    fn sub(self, rhs: M31<T>) -> Self::Output {
        M31(self.0.into() - rhs.0.into())
    }
}

/// Addition in M31 arithmetic. Widens into an `i64`.
impl<T: Into<i64>, K: Into<i64>> Add<M31<T>> for M31<K> {
    type Output = M31<i64>;

    fn add(self, rhs: M31<T>) -> Self::Output {
        M31(self.0.into() + rhs.0.into())
    }
}

/// Left shift on an `i62` accumulator.
///
/// A fully reduced residue has room for at most two 15-bit left shifts (8-th
/// root of unity).
impl<K: Into<i64>> Shl<u8> for M31<K> {
    type Output = M31<i64>;
    fn shl(self, rhs: u8) -> Self::Output {
        M31(self.0.into() << rhs)
    }
}

#[cfg(kani)]
mod verification {
    use super::*;
    // Takes a signed 62-bit number and sign-extends it into a valid i64.
    fn sign_extend(x: u64) -> i64 {
        let sign = x >> 61;
        let sign = sign << 2 | sign << 1 | sign;
        ((sign << 61) | x) as i64
    }

    /// Proves that reducing an `i62` accumulator matches modulo p semantics.
    #[kani::proof]
    fn reduce_i64() {
        let x: u64 = kani::any::<u64>() & ((1 << 62) - 1);
        let x = sign_extend(x);
        assert_eq!(x.rem_euclid((1 << 31) - 1) as u32, x.reduce_fully())
    }

    // The proof for the multiplier is too slow. Therefore we model-check the
    // inner part. The input is slightly larger than what it would be within the
    // multiplier.
    /// Proves that one fold plus full reduction matches modulo p on `u64`.
    #[kani::proof]
    fn reduce_u64() {
        let x: u64 = kani::any::<u64>();
        assert_eq!(
            x.rem_euclid((1 << 31) - 1) as u32,
            reduce_round(x).reduce_fully()
        )
    }

    // Checking only `i64` does not cover the full `u32` range.
    /// Proves full reduction on all `u32` inputs.
    #[kani::proof]
    fn reduce_u32() {
        let x = kani::any::<u32>();
        assert_eq!(x.rem_euclid((1 << 31) - 1) as u32, x.reduce_fully())
    }
}
