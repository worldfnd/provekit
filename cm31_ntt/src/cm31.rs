/// Complex M31 field arithmetic.

use crate::rm31::{ RF, P };
use std::ops::{ Add, AddAssign, Sub, SubAssign, Neg, Mul, MulAssign };
use core::fmt::Display;
use std::convert::{ From, Into };
use num_traits::Zero;
use num_traits::identities::One;
use num_traits::pow::Pow;
use rand::distributions::{Distribution, Standard};
use rand::Rng;

#[derive(Copy, Clone, Debug)]
pub struct CF {
    pub(crate) a: RF, // the real part
    pub(crate) b: RF, // the imaginary part
}

// The 8th root of unity and its negation
pub const W_8: CF = CF { 
    a: RF { val: 0x00008000},
    b: RF { val: 0x00008000 }
};

pub const W_8_NEG_1: CF = CF {
    a: RF { val: 0x7fff7fff},
    b: RF { val: 0x7fff7fff }
};

// The 4th root of unity and its negation
pub const W_4: CF = CF {
    a: RF { val: 0x00000000},
    b: RF { val: 0x00000001 }
};

pub const W_4_NEG_1: CF = CF {
    a: RF { val: 0x7fffffff},
    b: RF { val: 0x7ffffffe }
};


/// Returns the 2nd to n-th roots of unity (inclusive).
pub fn gen_roots_of_unity(n: usize) -> Vec<CF> {
    assert!(n > 1);
    let w2 = CF::root_of_unity_2();
    let mut w = w2;
    let mut res = vec![w2];
    for _ in 2..n+1 {
        w = w.try_sqrt().unwrap();
        res.push(w);
    }
    res
}

impl CF {
    pub fn new(real: u32, imag: u32) -> CF {
        CF { a: RF::new(real), b: RF::new(imag) }
    }

    pub const fn real(self) -> RF {
        self.a
    }

    pub const fn imag(self) -> RF {
        self.b
    }

    pub fn mul_by_f(self, f: RF) -> CF {
        CF { 
            a: f * self.real(),
            b: f * self.imag(),
        }
    }

    pub fn try_inverse(&self) -> Option<Self> {
        if self.a.val == 0 && self.b.val == 0 {
            return None;
        }

        let a2b2 = (self.a * self.a + self.b * self.b).reduce();
        if a2b2.is_zero() {
            return None;
        }

        let a2b2_inv = a2b2.try_inverse().unwrap().reduce();
        debug_assert!((a2b2 * a2b2_inv).reduce() == RF::new(1));

        let neg_b = self.b.neg();
        let a_neg_b = CF { a: self.a, b: neg_b };

        let result = a_neg_b.mul_by_f(a2b2_inv);
        Some(result)
    }

    pub fn reduce(self) -> CF {
        CF { a: self.a.reduce(), b: self.b.reduce() }
    }

    pub fn root_of_unity_2() -> CF {
        CF::new(0x7ffffffe, 0)
    }

    /// Returns the 4th root of unity. Since there are 2 options for this value, select the one you
    /// want using the input `i`.
    /// The 4th root of unity is (0, +-1)
    /// The options denoted by `i` are:
    /// 0. ( 0,  v)
    /// 1. ( 0, -v)
    pub fn root_of_unity_4(i: u32) -> Result<CF, String> {
        assert!(i < 2);
        if i == 0 {
            return Ok(CF::new(0, 1));
        }
        if i == 1 {
            return Ok(CF::new(0, P - 1));
        }
        panic!("i must be 0 or 1");
    }

    /// Returns the 8th root of unity. Since there are 4 options for this value, select the one you
    /// want using the input `i`.
    /// The 8th root of unity is (+-2^15, +-2^15)
    /// Let v = 2^15
    /// The options denoted by `i` are:
    /// 0. ( v,  v)
    /// 1. ( v, -v)
    /// 2. (-v,  v)
    /// 3. (-v, -v)
    pub fn root_of_unity_8(i: u32) -> Result<CF, String> {
        assert!(i < 4);
        let v = 2u32.pow(15);
        let neg_v = P - v;
        // i = 0: (v, v)
        // i = 1: (v, -v)
        // i = 2: (-v, v)
        // i = 3: (-v, -v)
        if i == 0 {
            return Ok(CF::new(v, v));
        }
        if i == 1 {
            return Ok(CF::new(v, neg_v));
        }
        if i == 2 {
            return Ok(CF::new(neg_v, v));
        }
        if i == 3 {
            return Ok(CF::new(neg_v, neg_v));
        }
        panic!("i must be 0, 1, 2 or 3");
    }

    #[inline]
    pub fn mul_neg_1(self) -> Self {
        let c = self.a.neg();
        let d = self.b.neg();
        CF { a: c, b: d }
    }

    #[inline]
    pub fn mul_j(self) -> Self {
        CF { a: self.b.neg(), b: self.a }
    }

    /// Attempts to compute a square root of a complex element in CF.
    pub fn try_sqrt(self) -> Option<CF> {
        if self.is_zero() {
            return Some(CF::zero());
        }

        let two = RF::new(2);
        // 2 is invertible in RF; unwrap is safe since P ≠ 2.
        let two_inv = two.try_inverse().unwrap();
        let a = self.a;
        let b = self.b;
        // Compute r = sqrt(a^2 + b^2) in RF.
        let norm = (a * a + b * b).reduce();
        let r = norm.try_sqrt()?;
        
        // Candidate branch 1: try x = sqrt((a + r)/2).
        let candidate_x2 = ((a + r) * two_inv).reduce();
        if let Some(x) = candidate_x2.try_sqrt() {
            // If x ≠ 0 then we can recover y as b/(2x).
            if !x.is_zero() {
                let x_inv = x.try_inverse().unwrap();
                let y = (b * two_inv * x_inv).reduce();
                let candidate = CF { a: x, b: y }.reduce();
                if candidate * candidate == self {
                    return Some(candidate);
                }
            }
        }
        
        // Candidate branch 2: try y = sqrt((r - a)/2).
        let candidate_y2 = ((r - a) * two_inv).reduce();
        if let Some(y) = candidate_y2.try_sqrt() {
            if !y.is_zero() {
                let y_inv = y.try_inverse().unwrap();
                let x = (b * two_inv * y_inv).reduce();
                let candidate = CF { a: x, b: y }.reduce();
                if candidate * candidate == self {
                    return Some(candidate);
                }
            }
        }

        None
    }
}

impl Zero for CF {
    #[inline]
    fn zero() -> CF {
        CF::new(0, 0)
    }
    #[inline]
    fn is_zero(&self) -> bool {
        self.a.is_zero() && self.b.is_zero()
    }
}

impl One for CF {
    #[inline]
    fn one() -> CF {
        CF::new(1, 0)
    }
}

impl Into<CF> for u32 {
    #[inline]
    /// Converts a u32 into a CF where the real part is the specified u32, and the imaginary part
    /// is 0
    fn into(self) -> CF {
        CF::new(self, 0)
    }
}

impl Into<CF> for (u32, u32) {
    #[inline]
    fn into(self) -> CF {
        CF { a: RF::new(self.0), b: RF::new(self.1) }
    }
}

impl From<CF> for (u32, u32) {
    #[inline]
    fn from(f: CF) -> (u32, u32) {
        (f.a.reduce().val as u32, f.b.reduce().val as u32)
    }
}

impl Add for CF {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let a = self.a;
        let b = self.b;
        let c = rhs.a;
        let d = rhs.b;

        CF { a: a + c, b: b + d }
    }
}

impl AddAssign for CF {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for CF {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let a = self.a;
        let b = self.b;
        let c = rhs.a;
        let d = rhs.b;

        CF { a: a - c, b: b - d }
    }
}

impl SubAssign for CF {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for CF {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        // (a, b) * (c, d) = (ac - bd, ad + bc)
        // This implementation uses Karatsuba:
        // (ac - bd, (a + b)(c + d) - ac - bd)
        let a = self.a;
        let b = self.b;
        let c = rhs.a;
        let d = rhs.b;

        let ac = a * c;
        let bd = b * d;
        let real = ac - bd;
        let imag = ((a + b) * (c + d) - ac) - bd;

        CF { a: real, b: imag }
    }
}

impl MulAssign for CF {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Neg for CF {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        CF { a: -self.a, b: -self.b }
    }
}

impl PartialEq for CF {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b
    }
}

impl Eq for CF {}

impl Display for CF {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} + {}i", self.a, self.b)
    }
}

impl Pow<usize> for CF {
    type Output = CF;

    #[inline]
    fn pow(self, exp: usize) -> Self::Output {
        let mut result = CF::one();
        let mut base = self;
        let mut exp = exp;
        while exp > 0 {
            if exp % 2 == 1 {
                result *= base;
            }
            base *= base;
            exp /= 2;
        }
        result
    }
}

impl Distribution<CF> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> CF {
        CF {
            a: rng.r#gen(),
            b: rng.r#gen(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rm31::P;
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::SeedableRng;
    use num_traits::One;

    #[test]
    fn test_new() {
        assert_eq!(CF::new(0, 0).a.val, 0);
        assert_eq!(CF::new(1, 0).a.val, 1);
        assert_eq!(CF::new(0, 1).b.val, 1);
    }

    #[test]
    fn test_one() {
        assert_eq!(CF::one().a.val, 1);
        assert_eq!(CF::one().b.val, 0);
    }

    #[test]
    fn test_into() {
        let x: CF = 0u32.into();
        assert_eq!(x, CF::new(0, 0));
        
        let x: CF = 1u32.into();
        assert_eq!(x, CF::new(1, 0));

        let x: CF = (1u32, 2u32).into();
        assert_eq!(x, CF::new(1, 2));

        let y: (u32, u32) = x.into();
        assert_eq!(y, (1, 2));
    }

    #[test]
    fn test_add() {
        assert_eq!(CF::new(1, 0) + CF::new(1, 0), CF::new(2, 0));
        assert_eq!(CF::new(0, 1) + CF::new(0, 1), CF::new(0, 2));
        assert_eq!(CF::new(P - 1, P - 1) + CF::new(1, 2), CF::new(0, 1));
    }

    #[test]
    fn test_neg() {
        let x = CF::new(1, 2);
        assert_eq!(-x, CF::new(P - 1, P - 2));
    }

    #[test]
    fn test_mul() {
        assert_eq!(
            CF::new(2, 2) * CF::new(4, 5),
            CF::new(P - 2, 18)
        );
    }

    #[test]
    fn test_inverse() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        for _ in 0..1024 {
            let x: CF = rng.r#gen();
            let x_inv = CF::try_inverse(&x).unwrap();
            assert_eq!(x * x_inv, CF::new(1, 0));
        }
    }

    #[test]
    fn test_pow() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        for _ in 0..128 {
            let x: CF = rng.r#gen();
            let mut r = CF::one();
            for i in 0..1024 {
                assert_eq!(r, x.pow(i));
                r *= x;
            }
        }
    }

    fn do_root_of_unity_test(root: CF, n: usize) {
        let mut r = CF::one();
        let one = CF::one();
        for _ in 0..n - 1 {
            r = r * root;
            assert_ne!(r, one);
        }
        r = r * root;
        assert_eq!(r, one);
    }

    #[test]
    fn test_w4() {
        for i in 0..2 {
            do_root_of_unity_test(CF::root_of_unity_4(i).unwrap(), 4);
        }
    }

    #[test]
    fn test_w8() {
        for i in 0..4 {
            do_root_of_unity_test(CF::root_of_unity_8(i).unwrap(), 8);
        }
    }

    #[test]
    fn test_sqrt() {
        // TODO: figure out why it doesn't work when
        // v equals CF { a: RF { val: 53cd1db6 }, b: RF { val: 5ac2fbb3 } }
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let v: CF = rng.r#gen();
        let v = v.reduce();
        let v2 = (v * v).reduce();
        let s = v2.try_sqrt().unwrap();
        assert_eq!(s * s, v2);
    }

    #[test]
    fn test_w16() {
        let w8 = CF::root_of_unity_8(0).unwrap();
        let w16 = w8.try_sqrt().unwrap();
        do_root_of_unity_test(w16, 16);
    }

    #[test]
    fn test_w2() {
        let w4 = CF::root_of_unity_4(0).unwrap();
        let w2 = w4 * w4;
        do_root_of_unity_test(w2, 2);
    }

    #[test]
    fn test_w32() {
        let w8 = CF::root_of_unity_8(0).unwrap();
        let w16 = w8.try_sqrt().unwrap();
        let w32 = w16.try_sqrt().unwrap();
        do_root_of_unity_test(w32, 32);
    }

    #[test]
    fn test_gen_roots_of_unity() {
        let roots_of_unity = gen_roots_of_unity(21);
        for i in 0..roots_of_unity.len() {
            let w = roots_of_unity[i];
            do_root_of_unity_test(w, 2usize.pow(i as u32 + 1));
        }
    }

    #[test]
    fn test_opts() {
        // Test the optimized functions.
        let w = CF::root_of_unity_8(0).unwrap();
        let j = w.pow(2);
        let neg_1 = w.pow(4);

        let v: CF = CF::new(0x12345678, 0x87654321);
        let v_neg_1 = v.mul_neg_1();
        assert_eq!(v * neg_1, v_neg_1);

        let v_j = v.mul_j();
        assert_eq!(v * j, v_j);
    }
}
