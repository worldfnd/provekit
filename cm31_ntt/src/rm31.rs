use crate::m31::into_m31;
use core::fmt::Display;
use num_traits::{ Zero, One, Pow };
use std::ops::{ Add, AddAssign, Sub, SubAssign, Neg, Mul, MulAssign };
use std::convert::{ From, Into };
use rand::distributions::{Distribution, Standard};
use rand::Rng;

pub const P: u32 = 0x7fffffff;
pub const P_64: u64 = 0x7fffffff;
pub const P2: u64 = 0xfffffffe;
pub const P3: u64 = 0x17ffffffd;
pub const MASK: u64 = 0xffffffff;

// The redundant form of the M31 field. It consists of 31 lower bits (x_l) and the rest are higher
// bits (x_h).
// x = x_h * 2^32 + x_l
// See https://github.com/ingonyama-zk/papers/blob/main/Mersenne31_polynomial_arithmetic.pdf
#[derive(Copy, Clone, Debug)]
pub struct RF {
    pub(crate) val: u64,
}

pub fn reduce(value: u64) -> u64 {
    let x_l = value & 0xffffffff;
    let x_h = value >> 32;

    let mut r = x_h * 2 + x_l;
    while r >= P_64 {
        r -= P_64;
    }
    r
}

impl RF {
    #[inline]
    pub const fn new(value: u32) -> RF {
        RF { val: into_m31(value).val as u64 }
    }

    #[inline]
    pub fn reduce(self) -> RF {
        RF { val: reduce(self.val) }
    }

    #[inline]
    fn square(&self) -> Self {
        // From https://github.com/Plonky3/Plonky3/blob/main/field/src/field.rs
        self.clone() * self.clone()
    }

    #[inline]
    fn exp_power_of_2(&self, power_log: usize) -> Self {
        // From https://github.com/Plonky3/Plonky3/blob/main/field/src/field.rs
        let mut res = self.clone();
        for _ in 0..power_log {
            res = res.square();
        }
        res
    }

    #[inline]
    pub fn try_inverse(&self) -> Option<Self> {
        // From https://github.com/Plonky3/Plonky3/blob/6049a30c3b1f5351c3eb0f7c994dc97e8f68d10d/mersenne-31/src/lib.rs#L188
        if self.is_zero() {
            return None;
        }

        // self ** (P - 2) = self ** 0b1111111111111111111111111111101
        let p1 = self.clone();

        // Compute p1 ** 2147483645
        let p101 = p1.exp_power_of_2(2) * p1;
        let p1111 = p101.reduce().square() * p101;
        let p11111111 = p1111.reduce().exp_power_of_2(4) * p1111;
        let p111111110000 = p11111111.reduce().exp_power_of_2(4);
        let p111111111111 = p111111110000 * p1111;
        let p1111111111111111 = p111111110000.reduce().exp_power_of_2(4) * p11111111;
        let p1111111111111111111111111111 = p1111111111111111.reduce().exp_power_of_2(12) * p111111111111;
        let p1111111111111111111111111111101 =
            p1111111111111111111111111111.reduce().exp_power_of_2(3) * p101;
        Some(p1111111111111111111111111111101.reduce())
    }

    #[inline]
    pub fn mul_2exp_u64(&self, exp: u64) -> Self {
        // Adpated from https://github.com/Plonky3/Plonky3/blob/6049a30c3b1f5351c3eb0f7c994dc97e8f68d10d/mersenne-31/src/lib.rs#L162
        let reduced = reduce(self.val);
        let exp = exp % 31;
        let left = (reduced << exp) & P_64;
        let right = reduced >> (31 - exp);
        let rotated = left | right;
        Self::new(rotated as u32)
    }

    #[inline]
    pub fn div_2exp_u64(&self, exp: u64) -> Self {
        // Adpated from https://github.com/Plonky3/Plonky3/blob/6049a30c3b1f5351c3eb0f7c994dc97e8f68d10d/mersenne-31/src/lib.rs#L162
        let reduced = reduce(self.val);
        let exp = (exp % 31) as u8;
        let left =   reduced >> exp;
        let right = (reduced << (31 - exp)) & P_64;
        let rotated = left | right;
        Self::new(rotated as u32)
    }

    pub fn try_sqrt(&self) -> Option<RF> {
        if self.is_zero() {
            return Some(RF::zero());
        }
        // (P + 1) / 4 = 0x20000000
        let candidate = self.pow(0x20000000);
        if candidate.square().reduce() == self.reduce() {
            Some(candidate.reduce())
        } else {
            None
        }
    }
}

impl Into<RF> for u32 {
    #[inline]
    fn into(self) -> RF {
        RF::new(self)
    }
}

impl Into<RF> for u64 {
    #[inline]
    fn into(self) -> RF {
        RF { val: reduce(self) }
    }
}

impl From<RF> for u64 {
    #[inline]
    fn from(f: RF) -> u64 {
        f.val
    }
}

impl Zero for RF {
    #[inline]
    fn zero() -> Self {
        RF { val: 0 }
    }

    #[inline]
    fn is_zero(&self) -> bool {
        let reduced = self.reduce();
        reduced.val == 0
    }
}

impl One for RF {
    #[inline]
    fn one() -> Self {
        RF { val: 1 }
    }
}

impl Neg for RF {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        let tmp = P3 - (self.val & MASK);
        let msb = (tmp >> 32) & 1;
        let out = 2 * msb + (tmp & MASK);
        RF { val: out }
    }
}

impl Mul for RF {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        let tmp = self.val * rhs.val;
        let tmp = 2 * (tmp >> 32) + (tmp & MASK);
        let out = 2 * (tmp >> 32) + (tmp & MASK);
        RF { val: out }
    }
}

impl MulAssign for RF {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl PartialEq for RF {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        reduce(self.val) == reduce(other.val)
    }
}

impl Eq for RF {}

impl Ord for RF {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        reduce(self.val).cmp(&reduce(other.val))
    }
}

impl PartialOrd for RF {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Add for RF {
    type Output = Self;

    #[inline]
    /// The output may not be fully reduced
    fn add(self, rhs: Self) -> Self::Output {
        let mut tmp: u64 = self.val + rhs.val;
        let mut msb: u64 = (tmp >> 32) & 1;
        tmp = 2 * msb + (tmp & MASK);
        msb = (tmp >> 32) & 1;
        tmp = 2 * msb + (tmp & MASK);
        RF { val: tmp }
    }
}

impl AddAssign for RF {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for RF {
    type Output = Self;

    #[inline]
    /// The output may not be fully reduced
    fn sub(self, rhs: Self) -> Self::Output {
        let tmp: u64 = P3 + (self.val & MASK) - (rhs.val & MASK);
        let msb = (tmp >> 32) & 3;
        RF { val: 2 * msb + (tmp & MASK) }
    }
}

impl SubAssign for RF {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Pow<usize> for RF {
    type Output = RF;

    #[inline]
    fn pow(self, exp: usize) -> Self::Output {
        let mut result = RF::one();
        let mut base = self;
        let mut e = exp;
        while e > 0 {
            if e & 1 == 1 {
                result *= base;
            }
            base *= base;
            e >>= 1;
        }
        result
    }
}

impl Distribution<RF> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> RF {
        let threshold = u32::MAX - (u32::MAX % P);
        loop {
            let candidate = (rng.next_u32() >> 1) as u32;
            if candidate < threshold {
                return RF { val: (candidate % P) as u64 };
            }
        }
    }
}

impl Display for RF {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CASES: &[(u32, u32)] = &[
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
        (1234, 5678),
        (9999999, 5678),
        (P, P - 1),
        (P, P),
        (P, P + 1),
        (P - 1, P + 1),
        (P - 2, P + 2),
        (P + 2, P + 2),
        (0xffffffff, 0xffffffff),
        (0x1234, 0x5678),
        (0xabcd, 0x4680),
        (2, P - 1),
    ];

    #[test]
    fn test_new() {
        assert_eq!(RF::new(0).val, 0);
        assert_eq!(RF::new(1).val, 1);
        assert_eq!(RF::new(P + 1).val, 1);
    }

    #[test]
    fn test_reduce() {
        let v = 0xffffffffffffffff;
        let expected = v % P_64;
        let v31: RF = v.into();
        assert_eq!(expected, v31.val);

        let v = P_64 - 123;
        let expected = v % P_64;
        let v31: RF = v.into();
        assert_eq!(expected, v31.val);

        let v = P_64;
        let expected = v % P_64;
        let v31: RF = v.into();
        assert_eq!(expected, v31.val);

        let v = P_64 + 123;
        let expected = v % P_64;
        let v31: RF = v.into();
        assert_eq!(expected, v31.val);
    }

    #[test]
    fn test_add() {
        for (lhs, rhs) in TEST_CASES {
            let lhs: RF = (*lhs).into();
            let rhs: RF = (*rhs).into();
            
            // The result may not be fully reduced
            let expected = (lhs.val + rhs.val) % P_64;
            let result = (lhs + rhs).val % P_64;
            assert_eq!(expected, result);
        }
    }

    #[test]
    fn test_add_assign() {
        let mut expected = 0;
        let mut sum = RF::new(0);
        let vals = &[
            RF::new(0),
            RF::new(2),
            RF::new(P - 1),
            RF::new(1234),
        ];

        for v in vals {
            expected += v.val;
            expected %= P_64;

            sum += *v;
            assert_eq!(sum.val % P_64, expected % P_64);
        }
    }

    #[test]
    fn test_sub() {
        for (lhs, rhs) in TEST_CASES {
            let lhs: RF = (*lhs).into();
            let rhs: RF = (*rhs).into();
            
            // The result should be fully reduced even if the inputs are not
            let expected = if lhs.val > rhs.val {
                (lhs.val - rhs.val) % P_64
            } else {
                (P_64 - (rhs.val - lhs.val)) % P_64
            };
            let result = (lhs - rhs).val % P_64;
            assert_eq!(expected, result);
        }
    }

    #[test]
    fn test_sub_assign() {
        let mut expected = 0;
        let mut sum = RF::new(0);
        let vals = &[
            RF::new(0),
            RF::new(2),
            RF::new(P - 1),
            RF::new(1234),
        ];

        for v in vals {
            expected = if expected > v.val {
                expected - v.val
            } else {
                P_64 - (v.val - expected)
            };

            sum -= *v;
            assert_eq!(sum.val % P_64, expected % P_64);
        }
    }

    #[test]
    fn test_neg() {
        let vals: &[(u64, u64)] = &[
            (0, 0),
            (2, 0),
            (1234, 0),
            (P_64 - 1, 0),
            (P_64 - 2, 0),
            (P_64, 0),
            (P_64 + 1, 0),
            (P_64 + 2, 0),
            (P_64 + 1234, 0),
            (P_64 - 1, 1234),
        ];

        for v in vals {
            let x = RF::new(v.0 as u32) + RF::new(v.1 as u32);
            let n = x.neg().reduce();
            let mut e = P_64 - ((v.0 + v.1) % P_64);
            e = e % P_64;
            assert_eq!(n.val, e);
        }
    }

    #[test]
    fn test_mul() {
        for (lhs, rhs) in TEST_CASES {
            let lhs: RF = (*lhs).into();
            let rhs: RF = (*rhs).into();
            
            // The result may not be fully reduced
            let expected = (lhs.val * rhs.val) % P_64;
            let result = (lhs * rhs).val % P_64;
            assert_eq!(expected, result);
        }
    }

    #[test]
    fn test_mul_assign() {
        let vals = &[
            RF::new(0),
            RF::new(2),
            RF::new(1234),
            RF::new(P - 2),
            RF::new(P - 1),
            RF::new(P),
            RF::new(P + 1),
            RF::new(P + 2),
            RF::new(P + 1234),
        ];

        let mut expected = 1;
        let mut product = RF::new(1);
        for v in vals {
            expected *= v.val;
            expected %= P_64;
            product *= *v;
            assert_eq!(product.val % P_64, expected);
        }
    }

    #[test]
    fn test_inverse() {
        assert!(RF::new(0).try_inverse().is_none());

        let test_cases = [1, 2, 3, 4, 1024, 317002956, 2342343242];

        for t in test_cases {
            let a = RF::new(t);
            let a_inv = RF::try_inverse(&a).unwrap();
            assert_eq!(a * a_inv, RF::new(1));
        }
    }

    #[test]
    fn test_mul_2exp_u64() {
        assert_eq!(RF::new(0).mul_2exp_u64(0),  RF::new(0));
        assert_eq!(RF::new(1).mul_2exp_u64(0),  RF::new(1));
        assert_eq!(RF::new(1).mul_2exp_u64(1),  RF::new(2));
        assert_eq!(RF::new(1).mul_2exp_u64(2),  RF::new(4));
        assert_eq!(RF::new(2).mul_2exp_u64(30), RF::new(1));
    }

    #[test]
    fn test_div_2exp_u64() {
        assert_eq!(RF::new(4096).div_2exp_u64(10), RF::new(4));
    }

    #[test]
    fn test_add_without_reduce() {
        let e_x = P_64 - 1;
        let mut e_y = e_x;
        let x = RF::new(P - 1);
        let mut y = x;
        for _ in 0..1024 {
            y += x;
            let reduced = y.reduce();
            
            e_y = (e_y + e_x) % P_64;

            assert_eq!(reduced.val, e_y);
        }
    }

    #[test]
    fn test_sqrt() {
        let valid_test_cases = [
            RF::new(0),
            RF::new(1),
            RF::new(2),
            RF::new(4),
            RF::new(9),
            RF::new(16),
        ];

        for t in valid_test_cases {
            let s = t.try_sqrt().unwrap();
            let s2 = s.square().reduce();
            assert_eq!(s2, t);
        }

        let invalid_test_cases = [
            RF::new(3),
        ];

        for t in invalid_test_cases {
            let s = t.try_sqrt();
            assert!(s.is_none());
        }
    }
}
