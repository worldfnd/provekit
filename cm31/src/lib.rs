/// Safety: When modifying this file, rerun with Kani
use std::ops::{Add, Mul, Shl, Sub};

#[derive(Copy, Clone)]
pub struct M31<T>(T);

trait M31Reduce {
    fn reduce_u32(self) -> M31<u32>;
    fn full_reduce(self) -> u32;
}

/// Code operating on M31 integers will mostly be operation on i62 (i64).
///
/// All operations assume that i64 works is being treated as a i62 integer. No
/// newtype wrapper for i62 has been introduced to keep boilerplate to a
/// minimum. It is up to the user to make sure that the signed results stays
/// within 62 bits. As most operations will never reach 62 bits and using the
/// upper two bits would require an extra reduction round.
///
/// One way to think of it is that the upper three bits act as the sign but and
/// therefore can not be different for each other.
/// This also allows for efficient implementation on 64 bit register machines
impl M31Reduce for i64 {
    #[inline(always)]
    fn reduce_u32(self) -> M31<u32> {
        let reduced = reduce_round(one_complement(self)) as u32;
        M31(reduced)
    }

    #[inline(always)]
    fn full_reduce(self) -> u32 {
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

/// From an end user perspective u32 is for storage as staying within u32 has no
/// benefit on 64 bit machines. Internally it is used to reduce the operands
/// before multiplition such that only a single multiplication has to be done on
/// 64 bit machines.
impl M31Reduce for u32 {
    #[inline(always)]
    fn reduce_u32(self) -> M31<u32> {
        M31(self)
    }

    #[inline(always)]
    fn full_reduce(self) -> u32 {
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

/// Performs a single reduction round
///
/// Up to the caller to keep track of how many bits are actualy reduced.
#[inline(always)]
fn reduce_round(r: u64) -> i64 {
    let lo = r & ((1 << 31) - 1);
    let hi = r >> 31;
    (hi + lo) as i64
}

/// Assumes that the input fits in i62
///
/// By taking the one complement we can make use of the correspondence between
/// one complement and numbers modulo Mersenne numbers. Another way of seeing
/// this is going from signed 62 bit value to a unsigned 62 bit number
/// hence the type change.
fn one_complement(r: i64) -> u64 {
    // Relies on the *arithmic* shift right to extend the three bit sign bits to an
    // i64.
    let sign = r >> 61;
    // Use the sign information to turn into one complement and clear out the
    // redudant sign bits as these would lead to an overcorrection.
    ((r + sign) & ((1 << 62) - 1)) as u64
}

// The following traits reduce the boiler plate when working with M31 by taking
// on some of the widening and reducing required.

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

impl<T: Into<i64>, K: Into<i64>> Sub<M31<T>> for M31<K> {
    type Output = M31<i64>;

    fn sub(self, rhs: M31<T>) -> Self::Output {
        M31(self.0.into() - rhs.0.into())
    }
}

impl<T: Into<i64>, K: Into<i64>> Add<M31<T>> for M31<K> {
    type Output = M31<i64>;

    fn add(self, rhs: M31<T>) -> Self::Output {
        M31(self.0.into() + rhs.0.into())
    }
}

// TODO implement shift left
impl<K: Into<i64>> Shl<u8> for M31<K> {
    type Output = M31<i64>;
    // A fully reduced m31 has space for two 15 left shifts. So in practice there
    // might only be space for one left shift. In that case adding a reduction
    // might be the right thing to do.
    fn shl(self, rhs: u8) -> Self::Output {
        M31(self.0.into() << rhs)
    }
}

#[cfg(kani)]
mod verification {
    use crate::{reduce_round, M31Reduce, M31};
    // Takes a 62bit number and sign extends it into a valid i64
    fn sign_extend(x: u64) -> i64 {
        let sign = x >> 61;
        let sign = sign << 2 | sign << 1 | sign;
        ((sign << 61) | x) as i64
    }

    #[kani::proof]
    fn reduce_i64() {
        let x: u64 = kani::any::<u64>() & ((1 << 62) - 1);
        let x = sign_extend(x);
        assert_eq!(x.rem_euclid((1 << 31) - 1) as u32, x.full_reduce())
    }

    // The proof for the multiplier is too slow. Therefore we model check the inner
    // part. The input slightly larger than what it would be within the multiplier.
    #[kani::proof]
    fn reduce_u64() {
        let x: u64 = kani::any::<u64>();
        assert_eq!(
            x.rem_euclid((1 << 31) - 1) as u32,
            reduce_round(x).full_reduce()
        )
    }

    // Checking the reduction of i64 is not enough as it will not cover the full
    // range of u32. Other libraries use
    #[kani::proof]
    fn reduce_u32() {
        let x = kani::any::<u32>();
        assert_eq!(x.rem_euclid((1 << 31) - 1) as u32, x.full_reduce())
    }
}
