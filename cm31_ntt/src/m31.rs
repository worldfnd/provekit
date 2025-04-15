use core::fmt::Display;
use std::ops::{ Add, AddAssign, Sub, SubAssign, Neg, Mul, MulAssign };
use num_traits::{ Zero, One };
use std::convert::{ From, Into };

/// An implementation of non-redundant M31 field arithmetic. Some code is adapted from
/// Plonky3/mersenne-31. This file is just for reference as cm31.rs and ntt.rs rely on rm31.rs,
/// which uses the redundant representation.

// The field modulus: 2**31 - 1
pub const P: u32 = 0x7fffffff;

// The non-redundant form of the M31 field, which is just a u32.
#[derive(Copy, Clone, Debug)]
pub struct F {
    pub(crate) val: u32
}

#[inline]
pub const fn into_m31(v: u32) -> F {
    F { val: v % P }
}

impl F {
    #[inline]
    pub const fn new(value: u32) -> F {
        into_m31(value)
    }

    #[inline]
    pub fn mul_2exp_u64(&self, exp: u64) -> Self {
        // Adpated from https://github.com/Plonky3/Plonky3/blob/6049a30c3b1f5351c3eb0f7c994dc97e8f68d10d/mersenne-31/src/lib.rs#L162
        let exp = exp % 31;
        let left = (self.val << exp) & P;
        let right = self.val >> (31 - exp);
        let rotated = left | right;
        Self::new(rotated)
    }

    #[inline]
    pub fn div_2exp_u64(&self, exp: u64) -> Self {
        // Adpated from https://github.com/Plonky3/Plonky3/blob/6049a30c3b1f5351c3eb0f7c994dc97e8f68d10d/mersenne-31/src/lib.rs#L162
        let exp = (exp % 31) as u8;
        let left = self.val >> exp;
        let right = (self.val << (31 - exp)) & ((1 << 31) - 1);
        let rotated = left | right;
        Self::new(rotated)
    }

    #[inline]
    pub fn square(&self) -> Self {
        // From https://github.com/Plonky3/Plonky3/blob/main/field/src/field.rs
        self.clone() * self.clone()
    }

    #[inline]
    pub fn exp_power_of_2(&self, power_log: usize) -> Self {
        // From https://github.com/Plonky3/Plonky3/blob/main/field/src/field.rs
        let mut res = self.clone();
        for _ in 0..power_log {
            res = res.square();
        }
        res
    }

    pub fn try_inverse(&self) -> Option<Self> {
        // From https://github.com/Plonky3/Plonky3/blob/6049a30c3b1f5351c3eb0f7c994dc97e8f68d10d/mersenne-31/src/lib.rs#L188
        if self.is_zero() {
            return None;
        }

        // self ** (P - 2) =
        // self ** 2147483645 = self ** 0b1111111111111111111111111111101
        let p1 = *self;
        let p101 = p1.exp_power_of_2(2) * p1;
        let p1111 = p101.square() * p101;
        let p11111111 = p1111.exp_power_of_2(4) * p1111;
        let p111111110000 = p11111111.exp_power_of_2(4);
        let p111111111111 = p111111110000 * p1111;
        let p1111111111111111 = p111111110000.exp_power_of_2(4) * p11111111;
        let p1111111111111111111111111111 = p1111111111111111.exp_power_of_2(12) * p111111111111;
        let p1111111111111111111111111111101 =
            p1111111111111111111111111111.exp_power_of_2(3) * p101;
        Some(p1111111111111111111111111111101)
    }
}

impl Zero for F {
    #[inline]
    fn zero() -> Self {
        F { val: 0 }
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.val == 0
    }
}

impl One for F {
    #[inline]
    fn one() -> Self {
        F { val: 1 }
    }
}

impl Neg for F {
    type Output = Self;

    fn neg(self) -> Self {
        F { val: P - self.val }
    }
    
}

#[inline]
pub fn from_u62(v: u64) -> F {
    // The input must be at most 62 bits
    debug_assert!(v < (1 << 62));

    // The lower 31 bits
    let lo = v as u32 & P;

    // The higher 31 bits
    let hi = (v >> 31) as u32;

    F::new(lo) + F::new(hi)
}

impl Into<F> for u32 {
    #[inline]
    fn into(self) -> F {
        into_m31(self)
    }
}

impl From<F> for u32 {
    #[inline]
    fn from(f:F) -> u32 {
        f.val
    }
}

impl PartialEq for F {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.val == other.val
    }
}

impl Eq for F {}

impl Add for F {
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self {
        // This is from https://github.com/Plonky3/Plonky3/blob/6049a30c3b1f5351c3eb0f7c994dc97e8f68d10d/mersenne-31/src/lib.rs#L249
        let sum = self.val + other.val;
        let lsb = sum & P;
        let msb = sum >> 31;
        F::new(lsb + msb)
    }
}

impl AddAssign for F {
    #[inline]
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl Sub for F {
    type Output = Self;

    #[inline]
    fn sub(self, other: Self) -> Self {
        // From Plonky3/mersenne-31/src/mersenne_31.rs
        let (mut sub, over) = self.val.overflowing_sub(other.val);
        sub -= over as u32;
        Self::new(sub & P)
    }
}

impl SubAssign for F {
    #[inline]
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl Mul for F {
    type Output = Self;

    #[inline]
    fn mul(self, other: Self) -> Self {
        let prod = self.val as u64 * other.val as u64;
        from_u62(prod)
    }
}

impl MulAssign for F {
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

impl Ord for F {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.val.cmp(&other.val)
    }
}

impl PartialOrd for F {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for F {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.val)
    }
}

#[cfg(test)]
mod tests {
    use crate::m31::{F, P};
    use num::Zero;

    #[test]
    fn test_new() {
        assert_eq!(F::new(P), F::new(0));
        assert_eq!(F::new(0), F::new(0));
        assert_eq!(F::new(1), F::new(P + 1));
    }

    #[test]
    fn test_zero() {
        assert_eq!(F::zero(), F::new(0));
        assert_eq!(F::zero().val, 0);
    }

    #[test]
    fn test_add() {
        assert_eq!(F::new(0) + F::new(0), F::new(0));
        assert_eq!(F::new(0) + F::new(1), F::new(1));
        assert_eq!(F::new(1) + F::new(2), F::new(3));
        assert_eq!(F::new(1) + F::new(0x7ffffffe), F::new(0));
        assert_eq!(F::new(0x7ffffffe) + F::new(0x7ffffffe), F::new(0x7ffffffd));
    }

    #[test]
    fn test_add_assign() {
        let mut f = F::new(0);
        f += F::new(0);
        assert_eq!(f, F::new(0));
        f += F::new(1);
        assert_eq!(f, F::new(1));
        f += F::new(2);
        assert_eq!(f, F::new(3));
        f += F::new(0x7ffffffe);
        assert_eq!(f, F::new(2));
    }

    #[test]
    fn test_sub() {
        assert_eq!(F::new(0) - F::new(0), F::new(0));
        assert_eq!(F::new(1) - F::new(1), F::new(0));
        assert_eq!(F::new(2) - F::new(1), F::new(1));
        assert_eq!(F::new(1) - F::new(P), F::new(1));
        assert_eq!(F::new(0) - F::new(1), F::new(P - 1));
        assert_eq!(F::new(P - 1) - F::new(P - 1), F::new(0));
    }

    #[test]
    fn test_cmp() {
        assert!(F::new(0) < F::new(1));
        assert!(F::new(0) <= F::new(0));
        assert!(F::new(0) <= F::new(1));
        assert!(F::new(1) > F::new(0));
        assert!(F::new(1) >= F::new(1));
        assert!(F::new(1) >= F::new(0));
    }

    #[test]
    fn test_sub_assign() {
        let mut f = F::new(3);
        f -= F::new(2);
        assert_eq!(f, F::new(1));
        f -= F::new(1);
        assert_eq!(f, F::new(0));
        f -= F::new(1);
        assert_eq!(f, F::new(P - 1));
        f -= F::new(1);
        assert_eq!(f, F::new(P - 2));
    }

    #[test]
    fn test_mul() {
        assert_eq!(F::new(0) * F::new(0), F::new(0));
        assert_eq!(F::new(1) * F::new(1), F::new(1));
        assert_eq!(F::new(2) * F::new(2), F::new(4));
        assert_eq!(F::new(P - 1) * F::new(2), F::new(((P - 1) * 2) % P));
    }

    #[test]
    fn test_mul_assign() {
        let mut f = F::new(1);
        f *= F::new(2);
        assert_eq!(f, F::new(2));
        f *= F::new(P - 1);
        assert_eq!(f, F::new((2 * (P - 1)) % P));
    }

    #[test]
    fn test_mul_2exp_u64() {
        assert_eq!(F::new(0).mul_2exp_u64(0), F::new(0));
        assert_eq!(F::new(1).mul_2exp_u64(0), F::new(1));
        assert_eq!(F::new(1).mul_2exp_u64(1), F::new(2));
        assert_eq!(F::new(1).mul_2exp_u64(2), F::new(4));
        assert_eq!(F::new(2).mul_2exp_u64(30), F::new(1));
    }

    #[test]
    fn test_div_2exp_u64() {
        assert_eq!(F::new(4096).div_2exp_u64(10), F::new(4));
    }

    #[test]
    fn test_inverse() {
        assert!(F::new(0).try_inverse().is_none());

        // TODO: figure out why this fails to calculate the inverse of 317002956
        let a = F::new(1234);
        let a_inv = F::try_inverse(&a).unwrap();
        assert_eq!(a * a_inv, F::new(1));
    }
}
