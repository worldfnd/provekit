use serde::{Serialize, Deserialize};
use core::fmt::Display;
use num_traits::{Zero, One, Pow};
use std::ops::{Add, AddAssign, Sub, SubAssign, Neg, Mul, MulAssign};
use std::convert::{From, Into};
use rand::distributions::{Distribution, Standard};
use rand::Rng;

pub const P: u32 = 0x7fffffff;
pub const P_64: u64 = 0x7fffffff;
pub const P3: u64 = 0x17ffffffd;
pub const MASK: u64 = 0xffffffff;

// The redundant form of the M31 field. It consists of 31 lower bits (x_l) and the rest are higher
// bits (x_h).
// 
// For non-redundant M31 representation:
//    x is 2^31 * x_h + x_l, and the reduced value is x_h + x_l.
// For redundant representation: 
//    x is 2^32 * x_h + x_l, and the (at least partially) reduced value is 2 * x_h + x_l.
// 
// See https://github.com/ingonyama-zk/papers/blob/main/Mersenne31_polynomial_arithmetic.pdf
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct RF {
    pub(crate) val: u32,
}

pub fn reduce(value: u32) -> u32 {
    let hi = value >> 31;
    let x = (value & P) + hi;
    if x == P { 0 } else { x }
}

impl RF {
    #[inline]
    pub fn new(value: u32) -> RF {
        RF { val: reduce(value) }
    }

    #[inline]
    pub fn reduce(self) -> RF {
        RF { val: reduce(self.val) }
    }

    #[inline]
    fn square(&self) -> Self {
        *self * *self
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

        let fully_reduced = p1111111111111111111111111111101.reduce().val % P;
        Some(RF::new(fully_reduced))
    }

    pub fn mul_2exp_u64(&self, exp: u64) -> Self {
        // Adpated from https://github.com/Plonky3/Plonky3/blob/6049a30c3b1f5351c3eb0f7c994dc97e8f68d10d/mersenne-31/src/lib.rs#L162
        let reduced = reduce(self.val);
        let exp = exp % 31;
        let left = (reduced << exp) & P;
        let right = reduced >> (31 - exp);
        let rotated = left | right;
        Self::new(rotated as u32)
    }

    pub fn div_2exp_u64(&self, exp: u64) -> Self {
        // Adpated from https://github.com/Plonky3/Plonky3/blob/6049a30c3b1f5351c3eb0f7c994dc97e8f68d10d/mersenne-31/src/lib.rs#L162
        let reduced = reduce(self.val);
        let exp = (exp % 31) as u8;
        let left =   reduced >> exp;
        let right = (reduced << (31 - exp)) & P;
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

    pub fn mul_by_2_15(&self) -> Self {
        let x = reduce(self.val);
        let rotated = ((x << 15) & P) | (x >> 16);
        RF { val: rotated }
    }

    pub fn mul_by_2_16(&self) -> Self {
        let x = reduce(self.val);
        let rotated = ((x << 16) & P) | (x >> 15);
        RF { val: rotated }
    }
}

impl Into<RF> for u32 {
    #[inline]
    fn into(self) -> RF {
        RF::new(self)
    }
}

impl From<RF> for u32 {
    #[inline]
    fn from(f: RF) -> u32 {
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
        let tmp   = P3 - self.val as u64;
        let carry = (tmp >> 32) as u32;
        let low   = tmp as u32;
        let out = low.wrapping_add(carry << 1);
        RF { val: out }
    }
}

impl Mul for RF {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        let prod = self.val as u64 * rhs.val as u64;
        let hi  = prod >> 32;
        let lo  = prod & 0xffffffff;
        let tmp = lo + hi * 2;
        let hi2 = tmp >> 32;
        let lo2 = tmp & 0xffffffff;
        let out = (lo2 + hi2 * 2) as u32;
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
        self.val % P == other.val % P
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
        let tmp = self.val as u64 + rhs.val as u64;
        let carry = (tmp >> 32) as u32;
        let low   = tmp as u32;
        RF { val: low.wrapping_add(carry << 1) }
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
        let tmp: u64 = P3 + self.val as u64 - rhs.val as u64;
        let carry = (tmp >> 32) as u32;
        let low   = tmp as u32;
        RF { val: low.wrapping_add(carry << 1) }
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
                return RF { val: candidate % P };
            }
        }
    }
}

impl Display for RF {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.val.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;
    use rand_chacha::ChaCha8Rng;
    use rand::SeedableRng;

    const NUM_FUZZ_TESTS: usize = 1024;

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
        (P - 2, P - 2),
    ];

    #[test_case(0, 0)]
    #[test_case(1, 1)]
    #[test_case(P + 1, 1)]
    fn test_new(x: u32, y: u32) {
        assert_eq!(RF::new(x).val, y);
    }

    #[test_case(P - 123, (P - 123) % P; "P minus 123")]
    #[test_case(P + 123, 123; "P plus 123")]
    #[test_case(P, 0; "P")]
    fn test_reduce(x: u32, y: u32) {
        let a: RF = x.into();
        assert_eq!(a.val, y);
    }

    #[test]
    fn test_reduce_fuzz() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        for _ in 0..NUM_FUZZ_TESTS {
            let a: RF = rng.r#gen();
            let b: RF = rng.r#gen();
            let reduced = (a + b).reduce();
            let expected = RF::new((a.val + b.val) % P);
            assert_eq!(reduced.val, expected.val);
        }
    }

        // Helper function to test binary operations against test cases
    fn test_binary_op<F, G>(op_name: &str, rf_op: F, expected_op: G)
    where
        F: Fn(RF, RF) -> RF,
        G: Fn(u32, u32) -> u32,
    {
        let mut failing_test_cases = vec![];
        for (lhs, rhs) in TEST_CASES {
            let lhs_rf: RF = (*lhs).into();
            let rhs_rf: RF = (*rhs).into();
            
            let expected = expected_op(lhs_rf.val, rhs_rf.val);
            let result = (rf_op(lhs_rf, rhs_rf)).val % P;

            if expected != result {
                failing_test_cases.push((lhs_rf, rhs_rf));
            }
        }

        // Print all faling test cases. This is useful for debugging. I don't use test_case here
        // as I want to reuse TEST_CASES, and I ran into issues with test_case name clashes.
        if failing_test_cases.len() > 0 {
            println!("Failed {} test cases: {:?}", op_name, failing_test_cases);
        }
        assert_eq!(failing_test_cases.len(), 0);
    }

    #[test]
    fn test_add() {
        test_binary_op(
            "add",
            |a, b| a + b,
            |a, b| ((a as u64 + b as u64) % P_64) as u32
        );
    }

    #[test]
    fn test_add_fuzz() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        for _ in 0..NUM_FUZZ_TESTS {
            let a: RF = rng.r#gen();
            let b: RF = rng.r#gen();
            let sum = a + b;
            let expected = (a.val as u64 + b.val as u64) % P_64;
            assert_eq!(sum.val % P, expected as u32);
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
            expected %= P;

            sum += *v;
            assert_eq!(sum, RF::new(expected));
        }
    }

    #[test]
    fn test_sub() {
        test_binary_op(
            "sub",
            |a, b| a - b,
            |a, b| if a > b {
                (a - b) % P
            } else {
                (P - (b - a)) % P
            }
        );
    }
    
    #[test]
    fn test_sub_fuzz() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        for _ in 0..NUM_FUZZ_TESTS {
            let a: RF = rng.r#gen();
            let b: RF = rng.r#gen();
            let diff = a - b;
            let expected = if a.val > b.val {
                (a.val - b.val) % P
            } else {
                (P - (b.val - a.val)) % P
            };
            assert_eq!(diff.val % P, expected);
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
                P - (v.val - expected)
            };

            sum -= *v;
            assert_eq!(sum, RF::new(expected));
        }
    }

    #[test_case(0, 0)]
    #[test_case(2, 0)]
    #[test_case(1234, 0)]
    #[test_case(P - 1, 0)]
    #[test_case(P - 2, 0)]
    #[test_case(P, 0)]
    #[test_case(P, 1)]
    #[test_case(P, 2)]
    #[test_case(P, 1234)]
    fn test_neg(x: u32, y: u32) {
        let x = RF::new(x) + RF::new(y);
        let n = x.neg();
        let s = x + n;
        let expected = RF::new(0);
        assert_eq!(s, expected);
    }
    
    #[test]
    fn test_neg_fuzz() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        for _ in 0..NUM_FUZZ_TESTS {
            let a: RF = rng.r#gen();
            let neg_a = a.neg();
            
            // Test that a + (-a) = 0
            let sum = a + neg_a;
            assert_eq!(sum.reduce(), RF::zero());
            
            // Test that -(-a) = a
            let neg_neg_a = neg_a.neg();
            assert_eq!(neg_neg_a.reduce(), a.reduce());
        }
    }

    #[test]
    fn test_mul() {
        test_binary_op(
            "mul",
            |a, b| a * b,
            |a, b| ((a as u64 * b as u64) % P_64) as u32
        );
    }
    
    #[test]
    fn test_mul_fuzz() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        for _ in 0..NUM_FUZZ_TESTS {
            let a: RF = rng.r#gen();
            let b: RF = rng.r#gen();
            let product = a * b;
            let expected = (a.val as u64 * b.val as u64) % P_64;
            assert_eq!(product.val % P, expected as u32);
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
            expected %= P;
            product *= *v;
            assert_eq!(product.val % P, expected);
        }
    }

    #[test]
    fn test_inverse_zero() {
        assert!(RF::new(0).try_inverse().is_none());
    }

    #[test_case(1)]
    #[test_case(2)]
    #[test_case(3)]
    #[test_case(4)]
    #[test_case(1024)]
    #[test_case(317002956)]
    #[test_case(2342343242)]
    fn test_inverse(x: u32) {
        let a = RF::new(x);
        let a_inv = RF::try_inverse(&a).unwrap();
        assert_eq!(a * a_inv, RF::new(1));

        let b = RF::try_inverse(&a_inv).unwrap();
        assert_eq!(a_inv * b, RF::new(1));
    }

    #[test_case(0, 0, 0)]
    #[test_case(1, 0, 1)]
    #[test_case(1, 1, 2)]
    #[test_case(1, 2, 4)]
    #[test_case(2, 30, 1)]
    fn test_mul_2exp_u64(x: u32, y: u64, z: u32) {
        assert_eq!(RF::new(x).mul_2exp_u64(y),  RF::new(z));
    }

    #[test_case(4096, 10, 4)]
    fn test_div_2exp_u64(x: u32, y: u64, z: u32) {
        assert_eq!(RF::new(x).div_2exp_u64(y), RF::new(z));
    }

    #[test]
    fn test_add_without_reduce() {
        let e_x = P - 1;
        let mut e_y = e_x;
        let x = RF::new(P - 1);
        let mut y = x;
        for _ in 0..1024 {
            y += x;
            let reduced = y.reduce();
            
            e_y = (e_y + e_x) % P;

            assert_eq!(reduced.val, e_y);
        }
    }

    #[test_case(0)]
    #[test_case(1)]
    #[test_case(2)]
    #[test_case(4)]
    #[test_case(9)]
    #[test_case(16)]
    fn test_sqrt(x: u32) {
        let s = RF::new(x).try_sqrt().unwrap();
        let s2 = s.square().reduce();
        assert_eq!(s2, RF::new(x));
    }

    #[test_case(3)]
    fn test_sqrt_invalid(x: u32) {
        let s = RF::new(x).try_sqrt();
        assert!(s.is_none());
    }

    #[test_case(0, 0)]
    #[test_case(P_64, 123)]
    #[test_case(P_64 - 2, P_64 - 2)]
    fn test_mul_by_2_15(x: u64, y: u64) {
        let m = 0x8000;
        let expected = (x + y) * m % P_64;

        let prod = RF::new(x as u32) + RF::new(y as u32);
        let result = prod.mul_by_2_15();
        assert_eq!(result.val, expected as u32);
    }

    #[test]
    fn test_mul_by_2_15_fuzz() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let m = 0x8000;
        for _ in 0..NUM_FUZZ_TESTS {
            let a: RF = rng.r#gen();
            let b: RF = rng.r#gen();
            let x = a + b;
            let expected = x.val as u64 * m as u64 % P_64;
            let result = x.mul_by_2_15();
            assert_eq!(result.val, expected as u32);
        }
    }

    #[test_case(0, 0)]
    #[test_case(P_64, 123)]
    #[test_case(P_64 - 2, P_64 - 2)]
    fn test_mul_by_2_16(x: u64, y: u64) {
        let m = 0x10000;
        let expected = (x + y) * m % P_64;

        let prod = RF::new(x as u32) + RF::new(y as u32);
        let result = prod.mul_by_2_16();
        assert_eq!(result.val, expected as u32);
    }

    #[test]
    fn test_mul_by_2_16_fuzz() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let m = 0x10000;
        for _ in 0..NUM_FUZZ_TESTS {
            let a: RF = rng.r#gen();
            let b: RF = rng.r#gen();
            let x = a + b;
            let expected = x.val as u64 * m as u64 % P_64;
            let result = x.mul_by_2_16();
            assert_eq!(result.val, expected as u32);
        }
    }
}
