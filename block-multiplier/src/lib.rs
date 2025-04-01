#![feature(portable_simd)]

pub mod constants;
pub mod rtz;

use crate::constants::*;
use rtz::RTZ;
use seq_macro::seq;
use std::arch::aarch64::vcvtq_f64_u64;
use std::ops::BitAnd;
use std::simd::{Simd, StdFloat, num::SimdFloat};

/// Macro to extract a subarray from an array.
///
/// # Arguments
///
/// * `$t` - The source array
/// * `$b` - The starting index (base) in the source array
/// * `$l` - The length of the subarray to extract
///
/// This should be used over t[N..].try_into().unwrap() in getting a subarray. Using try_into+unwrap
/// introduces the eh_personality (exception handling)
///
/// # Example
///
/// ```
/// use block_multiplier::subarray;
/// let array = [1, 2, 3, 4, 5];
/// let sub = subarray!(array, 1, 3); // Creates [2, 3, 4]
/// ```
#[macro_export]
macro_rules! subarray {

    ($t:expr, $b: literal, $l: literal) => {
        {
        use seq_macro::seq;
        let t = $t;
        let mut s = [0;$l];

        // The compiler does not detect out-of-bounds when using `for` therefore `seq!` is used here
        seq!(i in 0..$l {
            s[i] = t[$b+i];
        });
        s
    }
    };
}

#[inline]
pub fn block_multiplier(
    _rtz: &RTZ, // Proof that the mode has been set to RTZ
    s0_a: [u64; 4],
    s0_b: [u64; 4],
    v0_a: [u64; 4],
    v0_b: [u64; 4],
    v1_a: [u64; 4],
    v1_b: [u64; 4],
) -> ([u64; 4], [u64; 4], [u64; 4]) {
    // -- [VECTOR] ---------------------------------------------------------------------------------
    let v0_a = u256_to_u260_shl2_simd(transpose_u256_to_simd([v0_a, v1_a]));
    let v0_b = u256_to_u260_shl2_simd(transpose_u256_to_simd([v0_b, v1_b]));

    let mut t: [Simd<u64, 2>; 10] = [Simd::splat(0); 10];
    t[0] = Simd::splat(make_initial(1, 0));
    t[9] = Simd::splat(make_initial(0, 6));
    t[1] = Simd::splat(make_initial(2, 1));
    t[8] = Simd::splat(make_initial(6, 7));
    t[2] = Simd::splat(make_initial(3, 2));
    t[7] = Simd::splat(make_initial(7, 8));
    t[3] = Simd::splat(make_initial(4, 3));
    t[6] = Simd::splat(make_initial(8, 9));
    t[4] = Simd::splat(make_initial(10, 4));
    t[5] = Simd::splat(make_initial(9, 10));

    let avi: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[0].into()).into() };
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[0].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[0 + 0 + 1] += p_hi.to_bits();
    t[0 + 0] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[1].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[0 + 1 + 1] += p_hi.to_bits();
    t[0 + 1] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[2].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[0 + 2 + 1] += p_hi.to_bits();
    t[0 + 2] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[3].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[0 + 3 + 1] += p_hi.to_bits();
    t[0 + 3] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[4].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[0 + 4 + 1] += p_hi.to_bits();
    t[0 + 4] += p_lo.to_bits();
    let avi: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[1].into()).into() };
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[0].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[1 + 0 + 1] += p_hi.to_bits();
    t[1 + 0] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[1].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[1 + 1 + 1] += p_hi.to_bits();
    t[1 + 1] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[2].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[1 + 2 + 1] += p_hi.to_bits();
    t[1 + 2] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[3].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[1 + 3 + 1] += p_hi.to_bits();
    t[1 + 3] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[4].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[1 + 4 + 1] += p_hi.to_bits();
    t[1 + 4] += p_lo.to_bits();
    let avi: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[2].into()).into() };
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[0].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[2 + 0 + 1] += p_hi.to_bits();
    t[2 + 0] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[1].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[2 + 1 + 1] += p_hi.to_bits();
    t[2 + 1] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[2].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[2 + 2 + 1] += p_hi.to_bits();
    t[2 + 2] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[3].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[2 + 3 + 1] += p_hi.to_bits();
    t[2 + 3] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[4].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[2 + 4 + 1] += p_hi.to_bits();
    t[2 + 4] += p_lo.to_bits();
    let avi: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[3].into()).into() };
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[0].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[3 + 0 + 1] += p_hi.to_bits();
    t[3 + 0] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[1].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[3 + 1 + 1] += p_hi.to_bits();
    t[3 + 1] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[2].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[3 + 2 + 1] += p_hi.to_bits();
    t[3 + 2] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[3].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[3 + 3 + 1] += p_hi.to_bits();
    t[3 + 3] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[4].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[3 + 4 + 1] += p_hi.to_bits();
    t[3 + 4] += p_lo.to_bits();
    let avi: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[4].into()).into() };
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[0].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[4 + 0 + 1] += p_hi.to_bits();
    t[4 + 0] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[1].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[4 + 1 + 1] += p_hi.to_bits();
    t[4 + 1] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[2].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[4 + 2 + 1] += p_hi.to_bits();
    t[4 + 2] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[3].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[4 + 3 + 1] += p_hi.to_bits();
    t[4 + 3] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_b[4].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[4 + 4 + 1] += p_hi.to_bits();
    t[4 + 4] += p_lo.to_bits();

    t[1] += t[0] >> 52;
    t[2] += t[1] >> 52;
    t[3] += t[2] >> 52;
    t[4] += t[3] >> 52;

    let r0 = smult_noinit_simd(t[0].bitand(Simd::splat(MASK52)), RHO_4);
    let r1 = smult_noinit_simd(t[1].bitand(Simd::splat(MASK52)), RHO_3);
    let r2 = smult_noinit_simd(t[2].bitand(Simd::splat(MASK52)), RHO_2);
    let r3 = smult_noinit_simd(t[3].bitand(Simd::splat(MASK52)), RHO_1);

    let s = [t[4], t[5], t[6], t[7], t[8], t[9]];

    let s = addv_simd(r3, addv_simd(addv_simd(s, r0), addv_simd(r1, r2)));

    let m = (s[0] * Simd::splat(U52_NP0)).bitand(Simd::splat(MASK52));
    let mp = smult_noinit_simd(m, U52_P);

    let resolve = resolve_simd_add_truncate(s, mp);
    let u256_result = u260_to_u256_simd(resolve);
    let v = transpose_simd_to_u256(u256_result);

    // ---------------------------------------------------------------------------------------------
    // -- [SCALAR] ---------------------------------------------------------------------------------
    let mut s0_t = [0_u64; 8];
    let mut carry = 0;
    (s0_t[0], carry) = carrying_mul_add(s0_a[0], s0_b[0], s0_t[0], carry);
    (s0_t[1], carry) = carrying_mul_add(s0_a[0], s0_b[1], s0_t[1], carry);
    (s0_t[2], carry) = carrying_mul_add(s0_a[0], s0_b[2], s0_t[2], carry);
    (s0_t[3], carry) = carrying_mul_add(s0_a[0], s0_b[3], s0_t[3], carry);
    s0_t[4] = carry;
    carry = 0;
    (s0_t[1], carry) = carrying_mul_add(s0_a[1], s0_b[0], s0_t[1], carry);
    (s0_t[2], carry) = carrying_mul_add(s0_a[1], s0_b[1], s0_t[2], carry);
    (s0_t[3], carry) = carrying_mul_add(s0_a[1], s0_b[2], s0_t[3], carry);
    (s0_t[4], carry) = carrying_mul_add(s0_a[1], s0_b[3], s0_t[4], carry);
    s0_t[5] = carry;
    carry = 0;
    (s0_t[2], carry) = carrying_mul_add(s0_a[2], s0_b[0], s0_t[2], carry);
    (s0_t[3], carry) = carrying_mul_add(s0_a[2], s0_b[1], s0_t[3], carry);
    (s0_t[4], carry) = carrying_mul_add(s0_a[2], s0_b[2], s0_t[4], carry);
    (s0_t[5], carry) = carrying_mul_add(s0_a[2], s0_b[3], s0_t[5], carry);
    s0_t[6] = carry;
    carry = 0;
    (s0_t[3], carry) = carrying_mul_add(s0_a[3], s0_b[0], s0_t[3], carry);
    (s0_t[4], carry) = carrying_mul_add(s0_a[3], s0_b[1], s0_t[4], carry);
    (s0_t[5], carry) = carrying_mul_add(s0_a[3], s0_b[2], s0_t[5], carry);
    (s0_t[6], carry) = carrying_mul_add(s0_a[3], s0_b[3], s0_t[6], carry);
    s0_t[7] = carry;

    let mut s0_r1 = [0_u64; 5];
    (s0_r1[0], s0_r1[1]) = carrying_mul_add(s0_t[0], U64_I3[0], s0_r1[0], 0);
    (s0_r1[1], s0_r1[2]) = carrying_mul_add(s0_t[0], U64_I3[1], s0_r1[1], 0);
    (s0_r1[2], s0_r1[3]) = carrying_mul_add(s0_t[0], U64_I3[2], s0_r1[2], 0);
    (s0_r1[3], s0_r1[4]) = carrying_mul_add(s0_t[0], U64_I3[3], s0_r1[3], 0);

    let mut s0_r2 = [0_u64; 5];
    (s0_r2[0], s0_r2[1]) = carrying_mul_add(s0_t[1], U64_I2[0], s0_r2[0], 0);
    (s0_r2[1], s0_r2[2]) = carrying_mul_add(s0_t[1], U64_I2[1], s0_r2[1], 0);
    (s0_r2[2], s0_r2[3]) = carrying_mul_add(s0_t[1], U64_I2[2], s0_r2[2], 0);
    (s0_r2[3], s0_r2[4]) = carrying_mul_add(s0_t[1], U64_I2[3], s0_r2[3], 0);

    let mut s0_r3 = [0_u64; 5];
    (s0_r3[0], s0_r3[1]) = carrying_mul_add(s0_t[2], U64_I1[0], s0_r3[0], 0);
    (s0_r3[1], s0_r3[2]) = carrying_mul_add(s0_t[2], U64_I1[1], s0_r3[1], 0);
    (s0_r3[2], s0_r3[3]) = carrying_mul_add(s0_t[2], U64_I1[2], s0_r3[2], 0);
    (s0_r3[3], s0_r3[4]) = carrying_mul_add(s0_t[2], U64_I1[3], s0_r3[3], 0);

    let s0_s = addv(addv(subarray!(s0_t, 3, 5), s0_r1), addv(s0_r2, s0_r3));

    let s0_m = U64_MU0.wrapping_mul(s0_s[0]);
    let mut s0_mp = [0_u64; 5];
    (s0_mp[0], s0_mp[1]) = carrying_mul_add(s0_m, P[0], s0_mp[0], 0);
    (s0_mp[1], s0_mp[2]) = carrying_mul_add(s0_m, P[1], s0_mp[1], 0);
    (s0_mp[2], s0_mp[3]) = carrying_mul_add(s0_m, P[2], s0_mp[2], 0);
    (s0_mp[3], s0_mp[4]) = carrying_mul_add(s0_m, P[3], s0_mp[3], 0);

    let s0 = subarray!(addv(s0_s, s0_mp), 1, 4);
    // ---------------------------------------------------------------------------------------------
    (s0, v[0], v[1])
}
// -------------------------------------------------------------------------------------------------

#[inline(always)]
fn addv<const N: usize>(mut a: [u64; N], b: [u64; N]) -> [u64; N] {
    let mut carry = 0u64;
    for i in 0..N {
        let (sum1, overflow1) = a[i].overflowing_add(b[i]);
        let (sum2, overflow2) = sum1.overflowing_add(carry);
        a[i] = sum2;
        carry = (overflow1 as u64) + (overflow2 as u64);
    }
    a
}

// -- [SIMD UTILS] ---------------------------------------------------------------------------------

#[inline(always)]
const fn make_initial(low_count: usize, high_count: usize) -> u64 {
    let val = high_count * 0x467 + low_count * 0x433;
    -((val as i64 & 0xFFF) << 52) as u64
}

#[inline(always)]
fn transpose_u256_to_simd(limbs: [[u64; 4]; 2]) -> [Simd<u64, 2>; 4] {
    // This does not issue multiple ldp and zip which might be marginally faster.
    [
        Simd::from_array([limbs[0][0], limbs[1][0]]),
        Simd::from_array([limbs[0][1], limbs[1][1]]),
        Simd::from_array([limbs[0][2], limbs[1][2]]),
        Simd::from_array([limbs[0][3], limbs[1][3]]),
    ]
}

#[inline(always)]
fn transpose_simd_to_u256(limbs: [Simd<u64, 2>; 4]) -> [[u64; 4]; 2] {
    let mut result = [[0; 4]; 2];
    for i in 0..limbs.len() {
        let tmp = limbs[i].to_array();
        result[0][i] = tmp[0];
        result[1][i] = tmp[1];
    }
    result
}

#[inline(always)]
fn u256_to_u260_shl2_simd(limbs: [Simd<u64, 2>; 4]) -> [Simd<u64, 2>; 5] {
    let [l0, l1, l2, l3] = limbs;
    [
        (l0 << 2) & Simd::splat(MASK52),
        ((l0 >> 50) | (l1 << 14)) & Simd::splat(MASK52),
        ((l1 >> 38) | (l2 << 26)) & Simd::splat(MASK52),
        ((l2 >> 26) | (l3 << 38)) & Simd::splat(MASK52),
        l3 >> 14,
    ]
}

#[inline(always)]
fn u260_to_u256_simd(limbs: [Simd<u64, 2>; 5]) -> [Simd<u64, 2>; 4] {
    let [l0, l1, l2, l3, l4] = limbs;
    [
        l0 | (l1 << 52),
        (l1 >> 12) | (l2 << 40),
        (l2 >> 24) | (l3 << 28),
        (l3 >> 36) | (l4 << 16),
    ]
}

#[inline(always)]
fn smult_noinit_simd(s: Simd<u64, 2>, v: [u64; 5]) -> [Simd<u64, 2>; 6] {
    let mut t = [Simd::splat(0); 6];
    let s: Simd<f64, 2> = unsafe { vcvtq_f64_u64(s.into()).into() };

    for i in 0..v.len() {
        let p_hi = s.mul_add(Simd::splat(v[i] as f64), Simd::splat(C1));
        let p_lo = s.mul_add(Simd::splat(v[i] as f64), Simd::splat(C2) - p_hi);
        t[i + 1] += p_hi.to_bits();
        t[i] += p_lo.to_bits();
    }
    t
}

#[inline(always)]
fn addv_simd<const N: usize>(
    mut va: [Simd<u64, 2>; N],
    vb: [Simd<u64, 2>; N],
) -> [Simd<u64, 2>; N] {
    for i in 0..va.len() {
        va[i] += vb[i];
    }
    va
}

#[inline(always)]
fn resolve_simd_add_truncate(s: [Simd<u64, 2>; 6], mp: [Simd<u64, 2>; 6]) -> [Simd<u64, 2>; 5] {
    let mut out = [Simd::splat(0); 5];
    let mut carry = (s[0] + mp[0]) >> 52;
    for i in 0..5 {
        let tmp = s[i + 1] + mp[i + 1] + carry;
        out[i] = tmp.bitand(Simd::splat(MASK52));
        carry = tmp >> 52;
    }
    out
}

// -------------------------------------------------------------------------------------------------

#[inline(always)]
fn carrying_mul_add(a: u64, b: u64, add: u64, carry: u64) -> (u64, u64) {
    let c: u128 = a as u128 * b as u128 + carry as u128 + add as u128;
    (c as u64, (c >> 64) as u64)
}

#[cfg(test)]
mod tests {
    use crate::{block_multiplier, constants, rtz::RTZ};
    use primitive_types::U256;
    use rand::{Rng, SeedableRng, rngs};

    const OUTPUT_MAX: [u64; 4] = [
        0x783c14d81ffffffe,
        0xaf982f6f0c8d1edd,
        0x8f5f7492fcfd4f45,
        0x9f37631a3d9cbfac,
    ];

    fn mod_mul(a: U256, b: U256) -> U256 {
        let p = U256(constants::P);
        let mut c = [0u64; 4];
        c.copy_from_slice(&(a.full_mul(b) % p).0[0..4]);
        U256(c)
    }

    #[test]
    fn test_block_multiplier() {
        let mut rng = rngs::StdRng::seed_from_u64(0);
        let p = U256(constants::P);
        let r = U256(constants::R);
        let r_inv = U256(constants::R_INV);

        let mut s0_a_bytes = [0u8; 32];
        let mut s0_b_bytes = [0u8; 32];
        let mut v0_a_bytes = [0u8; 32];
        let mut v0_b_bytes = [0u8; 32];
        let mut v1_a_bytes = [0u8; 32];
        let mut v1_b_bytes = [0u8; 32];

        let rtz = RTZ::set().unwrap();

        for _ in 0..100000 {
            rng.fill(&mut s0_a_bytes);
            rng.fill(&mut s0_b_bytes);
            rng.fill(&mut v0_a_bytes);
            rng.fill(&mut v0_b_bytes);
            rng.fill(&mut v1_a_bytes);
            rng.fill(&mut v1_b_bytes);
            let s0_a = U256::from_little_endian(&s0_a_bytes) % p;
            let s0_b = U256::from_little_endian(&s0_b_bytes) % p;
            let v0_a = U256::from_little_endian(&v0_a_bytes) % p;
            let v0_b = U256::from_little_endian(&v0_b_bytes) % p;
            let v1_a = U256::from_little_endian(&v1_a_bytes) % p;
            let v1_b = U256::from_little_endian(&v1_b_bytes) % p;
            let s0_a_mont = mod_mul(s0_a, r);
            let s0_b_mont = mod_mul(s0_b, r);
            let v0_a_mont = mod_mul(v0_a, r);
            let v0_b_mont = mod_mul(v0_b, r);
            let v1_a_mont = mod_mul(v1_a, r);
            let v1_b_mont = mod_mul(v1_b, r);

            let (s0, v0, v1) = block_multiplier(
                &rtz,
                s0_a_mont.0,
                s0_b_mont.0,
                v0_a_mont.0,
                v0_b_mont.0,
                v1_a_mont.0,
                v1_b_mont.0,
            );
            assert!(U256(s0) < U256(OUTPUT_MAX));
            assert!(U256(v0) < U256(OUTPUT_MAX));
            assert!(U256(v1) < U256(OUTPUT_MAX));
            assert_eq!(mod_mul(U256(s0), r_inv), mod_mul(s0_a, s0_b));
            assert_eq!(mod_mul(U256(v0), r_inv), mod_mul(v0_a, v0_b));
            assert_eq!(mod_mul(U256(v1), r_inv), mod_mul(v1_a, v1_b));
        }
    }
}