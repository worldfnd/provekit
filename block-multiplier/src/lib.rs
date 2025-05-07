#![feature(portable_simd)]
#![feature(bigint_helper_methods)]

pub mod constants;

use {
    crate::constants::*,
    fp_rounding::{RoundingGuard, Zero},
    seq_macro::seq,
    std::{
        arch::aarch64::vcvtq_f64_u64,
        array,
        ops::BitAnd,
        simd::{
            Simd, StdFloat,
            cmp::SimdPartialEq,
            num::{SimdFloat, SimdInt, SimdUint},
        },
    },
};

/// Macro to extract a subarray from an array.
///
/// # Arguments
///
/// * `$t` - The source array
/// * `$b` - The starting index (base) in the source array
/// * `$l` - The length of the subarray to extract
///
/// This should be used over t[N..].try_into().unwrap() in getting a subarray.
/// Using try_into+unwrap introduces the eh_personality (exception handling)
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
pub fn scalar_sqr(a: [u64; 4]) -> [u64; 4] {
    // -- [SCALAR]
    // ---------------------------------------------------------------------------------
    let mut t = [0_u64; 8];

    let mut carry = 0;
    (t[0], carry) = carrying_mul_add(a[0], a[0], t[0], carry);
    (t[1], carry) = carrying_mul_add(a[0], a[1], t[1], carry);
    (t[2], carry) = carrying_mul_add(a[0], a[2], t[2], carry);
    (t[3], carry) = carrying_mul_add(a[0], a[3], t[3], carry);
    t[4] = carry;
    carry = 0;
    (t[1], carry) = carrying_mul_add(a[1], a[0], t[1], carry);
    (t[2], carry) = carrying_mul_add(a[1], a[1], t[2], carry);
    (t[3], carry) = carrying_mul_add(a[1], a[2], t[3], carry);
    (t[4], carry) = carrying_mul_add(a[1], a[3], t[4], carry);
    t[5] = carry;
    carry = 0;
    (t[2], carry) = carrying_mul_add(a[2], a[0], t[2], carry);
    (t[3], carry) = carrying_mul_add(a[2], a[1], t[3], carry);
    (t[4], carry) = carrying_mul_add(a[2], a[2], t[4], carry);
    (t[5], carry) = carrying_mul_add(a[2], a[3], t[5], carry);
    t[6] = carry;
    carry = 0;
    (t[3], carry) = carrying_mul_add(a[3], a[0], t[3], carry);
    (t[4], carry) = carrying_mul_add(a[3], a[1], t[4], carry);
    (t[5], carry) = carrying_mul_add(a[3], a[2], t[5], carry);
    (t[6], carry) = carrying_mul_add(a[3], a[3], t[6], carry);
    t[7] = carry;

    let mut s_r1 = [0_u64; 5];
    (s_r1[0], s_r1[1]) = carrying_mul_add(t[0], U64_I3[0], 0, 0);
    (s_r1[1], s_r1[2]) = carrying_mul_add(t[0], U64_I3[1], s_r1[1], 0);
    (s_r1[2], s_r1[3]) = carrying_mul_add(t[0], U64_I3[2], s_r1[2], 0);
    (s_r1[3], s_r1[4]) = carrying_mul_add(t[0], U64_I3[3], s_r1[3], 0);

    let mut s_r2 = [0_u64; 5];
    (s_r2[0], s_r2[1]) = carrying_mul_add(t[1], U64_I2[0], 0, 0);
    (s_r2[1], s_r2[2]) = carrying_mul_add(t[1], U64_I2[1], s_r2[1], 0);
    (s_r2[2], s_r2[3]) = carrying_mul_add(t[1], U64_I2[2], s_r2[2], 0);
    (s_r2[3], s_r2[4]) = carrying_mul_add(t[1], U64_I2[3], s_r2[3], 0);

    let mut s_r3 = [0_u64; 5];
    (s_r3[0], s_r3[1]) = carrying_mul_add(t[2], U64_I1[0], 0, 0);
    (s_r3[1], s_r3[2]) = carrying_mul_add(t[2], U64_I1[1], s_r3[1], 0);
    (s_r3[2], s_r3[3]) = carrying_mul_add(t[2], U64_I1[2], s_r3[2], 0);
    (s_r3[3], s_r3[4]) = carrying_mul_add(t[2], U64_I1[3], s_r3[3], 0);

    let s = addv(addv(subarray!(t, 3, 5), s_r1), addv(s_r2, s_r3));

    let m = U64_MU0.wrapping_mul(s[0]);
    let mut mp = [0_u64; 5];
    (mp[0], mp[1]) = carrying_mul_add(m, U64_P[0], mp[0], 0);
    (mp[1], mp[2]) = carrying_mul_add(m, U64_P[1], mp[1], 0);
    (mp[2], mp[3]) = carrying_mul_add(m, U64_P[2], mp[2], 0);
    (mp[3], mp[4]) = carrying_mul_add(m, U64_P[3], mp[3], 0);

    let r = reduce_ct(subarray!(addv(s, mp), 1, 4));
    // ---------------------------------------------------------------------------------------------
    r
}

#[inline]
pub fn scalar_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    // -- [SCALAR]
    // ---------------------------------------------------------------------------------
    let mut t = [0_u64; 8];

    let mut carry = 0;
    (t[0], carry) = carrying_mul_add(a[0], b[0], t[0], carry);
    (t[1], carry) = carrying_mul_add(a[0], b[1], t[1], carry);
    (t[2], carry) = carrying_mul_add(a[0], b[2], t[2], carry);
    (t[3], carry) = carrying_mul_add(a[0], b[3], t[3], carry);
    t[4] = carry;
    carry = 0;
    (t[1], carry) = carrying_mul_add(a[1], b[0], t[1], carry);
    (t[2], carry) = carrying_mul_add(a[1], b[1], t[2], carry);
    (t[3], carry) = carrying_mul_add(a[1], b[2], t[3], carry);
    (t[4], carry) = carrying_mul_add(a[1], b[3], t[4], carry);
    t[5] = carry;
    carry = 0;
    (t[2], carry) = carrying_mul_add(a[2], b[0], t[2], carry);
    (t[3], carry) = carrying_mul_add(a[2], b[1], t[3], carry);
    (t[4], carry) = carrying_mul_add(a[2], b[2], t[4], carry);
    (t[5], carry) = carrying_mul_add(a[2], b[3], t[5], carry);
    t[6] = carry;
    carry = 0;
    (t[3], carry) = carrying_mul_add(a[3], b[0], t[3], carry);
    (t[4], carry) = carrying_mul_add(a[3], b[1], t[4], carry);
    (t[5], carry) = carrying_mul_add(a[3], b[2], t[5], carry);
    (t[6], carry) = carrying_mul_add(a[3], b[3], t[6], carry);
    t[7] = carry;

    let mut s_r1 = [0_u64; 5];
    (s_r1[0], s_r1[1]) = carrying_mul_add(t[0], U64_I3[0], 0, 0);
    (s_r1[1], s_r1[2]) = carrying_mul_add(t[0], U64_I3[1], s_r1[1], 0);
    (s_r1[2], s_r1[3]) = carrying_mul_add(t[0], U64_I3[2], s_r1[2], 0);
    (s_r1[3], s_r1[4]) = carrying_mul_add(t[0], U64_I3[3], s_r1[3], 0);

    let mut s_r2 = [0_u64; 5];
    (s_r2[0], s_r2[1]) = carrying_mul_add(t[1], U64_I2[0], 0, 0);
    (s_r2[1], s_r2[2]) = carrying_mul_add(t[1], U64_I2[1], s_r2[1], 0);
    (s_r2[2], s_r2[3]) = carrying_mul_add(t[1], U64_I2[2], s_r2[2], 0);
    (s_r2[3], s_r2[4]) = carrying_mul_add(t[1], U64_I2[3], s_r2[3], 0);

    let mut s_r3 = [0_u64; 5];
    (s_r3[0], s_r3[1]) = carrying_mul_add(t[2], U64_I1[0], 0, 0);
    (s_r3[1], s_r3[2]) = carrying_mul_add(t[2], U64_I1[1], s_r3[1], 0);
    (s_r3[2], s_r3[3]) = carrying_mul_add(t[2], U64_I1[2], s_r3[2], 0);
    (s_r3[3], s_r3[4]) = carrying_mul_add(t[2], U64_I1[3], s_r3[3], 0);

    let s = addv(addv(subarray!(t, 3, 5), s_r1), addv(s_r2, s_r3));

    let m = U64_MU0.wrapping_mul(s[0]);
    let mut mp = [0_u64; 5];
    (mp[0], mp[1]) = carrying_mul_add(m, U64_P[0], mp[0], 0);
    (mp[1], mp[2]) = carrying_mul_add(m, U64_P[1], mp[1], 0);
    (mp[2], mp[3]) = carrying_mul_add(m, U64_P[2], mp[2], 0);
    (mp[3], mp[4]) = carrying_mul_add(m, U64_P[3], mp[3], 0);

    let r = reduce_ct(subarray!(addv(s, mp), 1, 4));
    // ---------------------------------------------------------------------------------------------
    r
}

#[inline]
pub fn simd_sqr(v0_a: [u64; 4], v1_a: [u64; 4]) -> ([u64; 4], [u64; 4]) {
    let v0_a = u256_to_u260_shl2_simd(transpose_u256_to_simd([v0_a, v1_a]));

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
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[0].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[0 + 0 + 1] += p_hi.to_bits();
    t[0 + 0] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[1].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[0 + 1 + 1] += p_hi.to_bits();
    t[0 + 1] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[2].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[0 + 2 + 1] += p_hi.to_bits();
    t[0 + 2] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[3].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[0 + 3 + 1] += p_hi.to_bits();
    t[0 + 3] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[4].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[0 + 4 + 1] += p_hi.to_bits();
    t[0 + 4] += p_lo.to_bits();

    let avi: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[1].into()).into() };
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[0].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[1 + 0 + 1] += p_hi.to_bits();
    t[1 + 0] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[1].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[1 + 1 + 1] += p_hi.to_bits();
    t[1 + 1] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[2].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[1 + 2 + 1] += p_hi.to_bits();
    t[1 + 2] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[3].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[1 + 3 + 1] += p_hi.to_bits();
    t[1 + 3] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[4].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[1 + 4 + 1] += p_hi.to_bits();
    t[1 + 4] += p_lo.to_bits();

    let avi: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[2].into()).into() };
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[0].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[2 + 0 + 1] += p_hi.to_bits();
    t[2 + 0] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[1].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[2 + 1 + 1] += p_hi.to_bits();
    t[2 + 1] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[2].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[2 + 2 + 1] += p_hi.to_bits();
    t[2 + 2] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[3].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[2 + 3 + 1] += p_hi.to_bits();
    t[2 + 3] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[4].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[2 + 4 + 1] += p_hi.to_bits();
    t[2 + 4] += p_lo.to_bits();

    let avi: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[3].into()).into() };
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[0].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[3 + 0 + 1] += p_hi.to_bits();
    t[3 + 0] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[1].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[3 + 1 + 1] += p_hi.to_bits();
    t[3 + 1] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[2].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[3 + 2 + 1] += p_hi.to_bits();
    t[3 + 2] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[3].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[3 + 3 + 1] += p_hi.to_bits();
    t[3 + 3] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[4].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[3 + 4 + 1] += p_hi.to_bits();
    t[3 + 4] += p_lo.to_bits();

    let avi: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[4].into()).into() };
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[0].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[4 + 0 + 1] += p_hi.to_bits();
    t[4 + 0] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[1].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[4 + 1 + 1] += p_hi.to_bits();
    t[4 + 1] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[2].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[4 + 2 + 1] += p_hi.to_bits();
    t[4 + 2] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[3].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[4 + 3 + 1] += p_hi.to_bits();
    t[4 + 3] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[4].into()).into() };
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

    let s = [
        r0[0] + r1[0] + r2[0] + r3[0] + t[4],
        r0[1] + r1[1] + r2[1] + r3[1] + t[5],
        r0[2] + r1[2] + r2[2] + r3[2] + t[6],
        r0[3] + r1[3] + r2[3] + r3[3] + t[7],
        r0[4] + r1[4] + r2[4] + r3[4] + t[8],
        r0[5] + r1[5] + r2[5] + r3[5] + t[9],
    ];

    let m = (s[0] * Simd::splat(U52_NP0)).bitand(Simd::splat(MASK52));
    let mp = smult_noinit_simd(m, U52_P);

    let reduced = reduce_ct_simd(addv_simd(s, mp));
    let u256_result = u260_to_u256_simd(reduced);
    let v = transpose_simd_to_u256(u256_result);
    (v[0], v[1])
}

#[inline]
pub fn simd_mul(
    v0_a: [u64; 4],
    v0_b: [u64; 4],
    v1_a: [u64; 4],
    v1_b: [u64; 4],
) -> ([u64; 4], [u64; 4]) {
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

    let s = [
        r0[0] + r1[0] + r2[0] + r3[0] + t[4],
        r0[1] + r1[1] + r2[1] + r3[1] + t[5],
        r0[2] + r1[2] + r2[2] + r3[2] + t[6],
        r0[3] + r1[3] + r2[3] + r3[3] + t[7],
        r0[4] + r1[4] + r2[4] + r3[4] + t[8],
        r0[5] + r1[5] + r2[5] + r3[5] + t[9],
    ];

    let m = (s[0] * Simd::splat(U52_NP0)).bitand(Simd::splat(MASK52));
    let mp = smult_noinit_simd(m, U52_P);

    let reduced = reduce_ct_simd(addv_simd(s, mp));
    let u256_result = u260_to_u256_simd(reduced);
    let v = transpose_simd_to_u256(u256_result);
    (v[0], v[1])
}

#[inline]
pub fn block_sqr(
    _rtz: &RoundingGuard<Zero>, // Proof that the mode has been set to RTZ
    s0_a: [u64; 4],
    v0_a: [u64; 4],
    v1_a: [u64; 4],
) -> ([u64; 4], [u64; 4], [u64; 4]) {
    // -- [SCALAR AB MULT]
    // -------------------------------------------------------------------------
    let mut s_t = [0_u64; 8];
    let mut carry = 0;
    (s_t[0], carry) = carrying_mul_add(s0_a[0], s0_a[0], s_t[0], carry);
    (s_t[1], carry) = carrying_mul_add(s0_a[0], s0_a[1], s_t[1], carry);
    (s_t[2], carry) = carrying_mul_add(s0_a[0], s0_a[2], s_t[2], carry);
    (s_t[3], carry) = carrying_mul_add(s0_a[0], s0_a[3], s_t[3], carry);
    s_t[4] = carry;
    carry = 0;
    (s_t[1], carry) = carrying_mul_add(s0_a[1], s0_a[0], s_t[1], carry);
    (s_t[2], carry) = carrying_mul_add(s0_a[1], s0_a[1], s_t[2], carry);
    (s_t[3], carry) = carrying_mul_add(s0_a[1], s0_a[2], s_t[3], carry);
    (s_t[4], carry) = carrying_mul_add(s0_a[1], s0_a[3], s_t[4], carry);
    s_t[5] = carry;
    carry = 0;
    (s_t[2], carry) = carrying_mul_add(s0_a[2], s0_a[0], s_t[2], carry);
    (s_t[3], carry) = carrying_mul_add(s0_a[2], s0_a[1], s_t[3], carry);
    (s_t[4], carry) = carrying_mul_add(s0_a[2], s0_a[2], s_t[4], carry);
    (s_t[5], carry) = carrying_mul_add(s0_a[2], s0_a[3], s_t[5], carry);
    s_t[6] = carry;
    carry = 0;
    (s_t[3], carry) = carrying_mul_add(s0_a[3], s0_a[0], s_t[3], carry);
    (s_t[4], carry) = carrying_mul_add(s0_a[3], s0_a[1], s_t[4], carry);
    (s_t[5], carry) = carrying_mul_add(s0_a[3], s0_a[2], s_t[5], carry);
    (s_t[6], carry) = carrying_mul_add(s0_a[3], s0_a[3], s_t[6], carry);
    s_t[7] = carry;
    // ---------------------------------------------------------------------------------------------
    // -- [VECTOR AB MULT]
    // -------------------------------------------------------------------------
    let v0_a = u256_to_u260_shl2_simd(transpose_u256_to_simd([v0_a, v1_a]));

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
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[0].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[0 + 0 + 1] += p_hi.to_bits();
    t[0 + 0] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[1].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[0 + 1 + 1] += p_hi.to_bits();
    t[0 + 1] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[2].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[0 + 2 + 1] += p_hi.to_bits();
    t[0 + 2] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[3].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[0 + 3 + 1] += p_hi.to_bits();
    t[0 + 3] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[4].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[0 + 4 + 1] += p_hi.to_bits();
    t[0 + 4] += p_lo.to_bits();
    let avi: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[1].into()).into() };
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[0].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[1 + 0 + 1] += p_hi.to_bits();
    t[1 + 0] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[1].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[1 + 1 + 1] += p_hi.to_bits();
    t[1 + 1] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[2].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[1 + 2 + 1] += p_hi.to_bits();
    t[1 + 2] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[3].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[1 + 3 + 1] += p_hi.to_bits();
    t[1 + 3] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[4].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[1 + 4 + 1] += p_hi.to_bits();
    t[1 + 4] += p_lo.to_bits();
    let avi: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[2].into()).into() };
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[0].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[2 + 0 + 1] += p_hi.to_bits();
    t[2 + 0] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[1].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[2 + 1 + 1] += p_hi.to_bits();
    t[2 + 1] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[2].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[2 + 2 + 1] += p_hi.to_bits();
    t[2 + 2] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[3].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[2 + 3 + 1] += p_hi.to_bits();
    t[2 + 3] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[4].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[2 + 4 + 1] += p_hi.to_bits();
    t[2 + 4] += p_lo.to_bits();
    let avi: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[3].into()).into() };
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[0].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[3 + 0 + 1] += p_hi.to_bits();
    t[3 + 0] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[1].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[3 + 1 + 1] += p_hi.to_bits();
    t[3 + 1] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[2].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[3 + 2 + 1] += p_hi.to_bits();
    t[3 + 2] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[3].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[3 + 3 + 1] += p_hi.to_bits();
    t[3 + 3] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[4].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[3 + 4 + 1] += p_hi.to_bits();
    t[3 + 4] += p_lo.to_bits();
    let avi: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[4].into()).into() };
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[0].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[4 + 0 + 1] += p_hi.to_bits();
    t[4 + 0] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[1].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[4 + 1 + 1] += p_hi.to_bits();
    t[4 + 1] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[2].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[4 + 2 + 1] += p_hi.to_bits();
    t[4 + 2] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[3].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[4 + 3 + 1] += p_hi.to_bits();
    t[4 + 3] += p_lo.to_bits();
    let bvj: Simd<f64, 2> = unsafe { vcvtq_f64_u64(v0_a[4].into()).into() };
    let p_hi = avi.mul_add(bvj, Simd::splat(C1));
    let p_lo = avi.mul_add(bvj, Simd::splat(C2) - p_hi);
    t[4 + 4 + 1] += p_hi.to_bits();
    t[4 + 4] += p_lo.to_bits();
    // ---------------------------------------------------------------------------------------------
    // -- [VECTOR REDUCE]
    // --------------------------------------------------------------------------
    t[1] += t[0] >> 52;
    t[2] += t[1] >> 52;
    t[3] += t[2] >> 52;
    t[4] += t[3] >> 52;

    let r0 = smult_noinit_simd(t[0].bitand(Simd::splat(MASK52)), RHO_4);
    let r1 = smult_noinit_simd(t[1].bitand(Simd::splat(MASK52)), RHO_3);
    let r2 = smult_noinit_simd(t[2].bitand(Simd::splat(MASK52)), RHO_2);
    let r3 = smult_noinit_simd(t[3].bitand(Simd::splat(MASK52)), RHO_1);

    let s = [
        r0[0] + r1[0] + r2[0] + r3[0] + t[4],
        r0[1] + r1[1] + r2[1] + r3[1] + t[5],
        r0[2] + r1[2] + r2[2] + r3[2] + t[6],
        r0[3] + r1[3] + r2[3] + r3[3] + t[7],
        r0[4] + r1[4] + r2[4] + r3[4] + t[8],
        r0[5] + r1[5] + r2[5] + r3[5] + t[9],
    ];
    // ---------------------------------------------------------------------------------------------
    // -- [SCALAR REDUCE]
    // --------------------------------------------------------------------------
    let mut s_r1 = [0_u64; 5];
    (s_r1[0], s_r1[1]) = carrying_mul_add(s_t[0], U64_I3[0], 0, 0);
    (s_r1[1], s_r1[2]) = carrying_mul_add(s_t[0], U64_I3[1], s_r1[1], 0);
    (s_r1[2], s_r1[3]) = carrying_mul_add(s_t[0], U64_I3[2], s_r1[2], 0);
    (s_r1[3], s_r1[4]) = carrying_mul_add(s_t[0], U64_I3[3], s_r1[3], 0);

    let mut s_r2 = [0_u64; 5];
    (s_r2[0], s_r2[1]) = carrying_mul_add(s_t[1], U64_I2[0], 0, 0);
    (s_r2[1], s_r2[2]) = carrying_mul_add(s_t[1], U64_I2[1], s_r2[1], 0);
    (s_r2[2], s_r2[3]) = carrying_mul_add(s_t[1], U64_I2[2], s_r2[2], 0);
    (s_r2[3], s_r2[4]) = carrying_mul_add(s_t[1], U64_I2[3], s_r2[3], 0);

    let mut s_r3 = [0_u64; 5];
    (s_r3[0], s_r3[1]) = carrying_mul_add(s_t[2], U64_I1[0], 0, 0);
    (s_r3[1], s_r3[2]) = carrying_mul_add(s_t[2], U64_I1[1], s_r3[1], 0);
    (s_r3[2], s_r3[3]) = carrying_mul_add(s_t[2], U64_I1[2], s_r3[2], 0);
    (s_r3[3], s_r3[4]) = carrying_mul_add(s_t[2], U64_I1[3], s_r3[3], 0);

    let s_s = addv(addv(subarray!(s_t, 3, 5), s_r1), addv(s_r2, s_r3));
    // ---------------------------------------------------------------------------------------------
    // -- [FINAL]
    // ----------------------------------------------------------------------------------
    let s_m = U64_MU0.wrapping_mul(s_s[0]);
    let mut s_mp = [0_u64; 5];
    (s_mp[0], s_mp[1]) = carrying_mul_add(s_m, U64_P[0], 0, 0);
    (s_mp[1], s_mp[2]) = carrying_mul_add(s_m, U64_P[1], s_mp[1], 0);
    (s_mp[2], s_mp[3]) = carrying_mul_add(s_m, U64_P[2], s_mp[2], 0);
    (s_mp[3], s_mp[4]) = carrying_mul_add(s_m, U64_P[3], s_mp[3], 0);
    let s0 = reduce_ct(subarray!(addv(s_s, s_mp), 1, 4));

    let m = (s[0] * Simd::splat(U52_NP0)).bitand(Simd::splat(MASK52));
    let mp = smult_noinit_simd(m, U52_P);
    let resolve = reduce_ct_simd(addv_simd(s, mp));
    let u256_result = u260_to_u256_simd(resolve);
    let v = transpose_simd_to_u256(u256_result);
    // ---------------------------------------------------------------------------------------------
    (s0, v[0], v[1])
}

#[inline]
pub fn block_mul(
    _rtz: &RoundingGuard<Zero>, // Proof that the mode has been set to RTZ
    s0_a: [u64; 4],
    s0_b: [u64; 4],
    v0_a: [u64; 4],
    v0_b: [u64; 4],
    v1_a: [u64; 4],
    v1_b: [u64; 4],
) -> ([u64; 4], [u64; 4], [u64; 4]) {
    // -- [SCALAR AB MULT]
    // -------------------------------------------------------------------------
    let mut s_t = [0_u64; 8];
    let mut carry = 0;
    (s_t[0], carry) = carrying_mul_add(s0_a[0], s0_b[0], s_t[0], carry);
    (s_t[1], carry) = carrying_mul_add(s0_a[0], s0_b[1], s_t[1], carry);
    (s_t[2], carry) = carrying_mul_add(s0_a[0], s0_b[2], s_t[2], carry);
    (s_t[3], carry) = carrying_mul_add(s0_a[0], s0_b[3], s_t[3], carry);
    s_t[4] = carry;
    carry = 0;
    (s_t[1], carry) = carrying_mul_add(s0_a[1], s0_b[0], s_t[1], carry);
    (s_t[2], carry) = carrying_mul_add(s0_a[1], s0_b[1], s_t[2], carry);
    (s_t[3], carry) = carrying_mul_add(s0_a[1], s0_b[2], s_t[3], carry);
    (s_t[4], carry) = carrying_mul_add(s0_a[1], s0_b[3], s_t[4], carry);
    s_t[5] = carry;
    carry = 0;
    (s_t[2], carry) = carrying_mul_add(s0_a[2], s0_b[0], s_t[2], carry);
    (s_t[3], carry) = carrying_mul_add(s0_a[2], s0_b[1], s_t[3], carry);
    (s_t[4], carry) = carrying_mul_add(s0_a[2], s0_b[2], s_t[4], carry);
    (s_t[5], carry) = carrying_mul_add(s0_a[2], s0_b[3], s_t[5], carry);
    s_t[6] = carry;
    carry = 0;
    (s_t[3], carry) = carrying_mul_add(s0_a[3], s0_b[0], s_t[3], carry);
    (s_t[4], carry) = carrying_mul_add(s0_a[3], s0_b[1], s_t[4], carry);
    (s_t[5], carry) = carrying_mul_add(s0_a[3], s0_b[2], s_t[5], carry);
    (s_t[6], carry) = carrying_mul_add(s0_a[3], s0_b[3], s_t[6], carry);
    s_t[7] = carry;
    // ---------------------------------------------------------------------------------------------
    // -- [VECTOR AB MULT]
    // -------------------------------------------------------------------------
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
    // ---------------------------------------------------------------------------------------------
    // -- [VECTOR REDUCE]
    // --------------------------------------------------------------------------
    t[1] += t[0] >> 52;
    t[2] += t[1] >> 52;
    t[3] += t[2] >> 52;
    t[4] += t[3] >> 52;

    let r0 = smult_noinit_simd(t[0].bitand(Simd::splat(MASK52)), RHO_4);
    let r1 = smult_noinit_simd(t[1].bitand(Simd::splat(MASK52)), RHO_3);
    let r2 = smult_noinit_simd(t[2].bitand(Simd::splat(MASK52)), RHO_2);
    let r3 = smult_noinit_simd(t[3].bitand(Simd::splat(MASK52)), RHO_1);

    let s = [
        r0[0] + r1[0] + r2[0] + r3[0] + t[4],
        r0[1] + r1[1] + r2[1] + r3[1] + t[5],
        r0[2] + r1[2] + r2[2] + r3[2] + t[6],
        r0[3] + r1[3] + r2[3] + r3[3] + t[7],
        r0[4] + r1[4] + r2[4] + r3[4] + t[8],
        r0[5] + r1[5] + r2[5] + r3[5] + t[9],
    ];
    // ---------------------------------------------------------------------------------------------
    // -- [SCALAR REDUCE]
    // --------------------------------------------------------------------------
    let mut s_r1 = [0_u64; 5];
    (s_r1[0], s_r1[1]) = carrying_mul_add(s_t[0], U64_I3[0], 0, 0);
    (s_r1[1], s_r1[2]) = carrying_mul_add(s_t[0], U64_I3[1], s_r1[1], 0);
    (s_r1[2], s_r1[3]) = carrying_mul_add(s_t[0], U64_I3[2], s_r1[2], 0);
    (s_r1[3], s_r1[4]) = carrying_mul_add(s_t[0], U64_I3[3], s_r1[3], 0);

    let mut s_r2 = [0_u64; 5];
    (s_r2[0], s_r2[1]) = carrying_mul_add(s_t[1], U64_I2[0], 0, 0);
    (s_r2[1], s_r2[2]) = carrying_mul_add(s_t[1], U64_I2[1], s_r2[1], 0);
    (s_r2[2], s_r2[3]) = carrying_mul_add(s_t[1], U64_I2[2], s_r2[2], 0);
    (s_r2[3], s_r2[4]) = carrying_mul_add(s_t[1], U64_I2[3], s_r2[3], 0);

    let mut s_r3 = [0_u64; 5];
    (s_r3[0], s_r3[1]) = carrying_mul_add(s_t[2], U64_I1[0], 0, 0);
    (s_r3[1], s_r3[2]) = carrying_mul_add(s_t[2], U64_I1[1], s_r3[1], 0);
    (s_r3[2], s_r3[3]) = carrying_mul_add(s_t[2], U64_I1[2], s_r3[2], 0);
    (s_r3[3], s_r3[4]) = carrying_mul_add(s_t[2], U64_I1[3], s_r3[3], 0);

    let s_s = addv(addv(subarray!(s_t, 3, 5), s_r1), addv(s_r2, s_r3));
    // ---------------------------------------------------------------------------------------------
    // -- [FINAL]
    // --------------------------------------------------------0-------------------------
    let s_m = U64_MU0.wrapping_mul(s_s[0]);
    let mut s_mp = [0_u64; 5];
    (s_mp[0], s_mp[1]) = carrying_mul_add(s_m, U64_P[0], 0, 0);
    (s_mp[1], s_mp[2]) = carrying_mul_add(s_m, U64_P[1], s_mp[1], 0);
    (s_mp[2], s_mp[3]) = carrying_mul_add(s_m, U64_P[2], s_mp[2], 0);
    (s_mp[3], s_mp[4]) = carrying_mul_add(s_m, U64_P[3], s_mp[3], 0);
    let s0 = reduce_ct(subarray!(addv(s_s, s_mp), 1, 4));

    let m = (s[0] * Simd::splat(U52_NP0)).bitand(Simd::splat(MASK52));
    let mp = smult_noinit_simd(m, U52_P);
    let resolve = reduce_ct_simd(addv_simd(s, mp));
    let u256_result = u260_to_u256_simd(resolve);
    let v = transpose_simd_to_u256(u256_result);
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

// -- [SIMD UTILS]
// ---------------------------------------------------------------------------------
#[inline(always)]
const fn make_initial(low_count: usize, high_count: usize) -> u64 {
    let val = high_count * 0x467 + low_count * 0x433;
    -((val as i64 & 0xfff) << 52) as u64
}

#[inline(always)]
pub fn transpose_u256_to_simd(limbs: [[u64; 4]; 2]) -> [Simd<u64, 2>; 4] {
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
    let tmp0 = limbs[0].to_array();
    let tmp1 = limbs[1].to_array();
    let tmp2 = limbs[2].to_array();
    let tmp3 = limbs[3].to_array();
    [[tmp0[0], tmp1[0], tmp2[0], tmp3[0]], [
        tmp0[1], tmp1[1], tmp2[1], tmp3[1],
    ]]
}

#[inline(always)]
pub fn u256_to_u260_shl2_simd(limbs: [Simd<u64, 2>; 4]) -> [Simd<u64, 2>; 5] {
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

    let p_hi_0 = s.mul_add(Simd::splat(v[0] as f64), Simd::splat(C1));
    let p_lo_0 = s.mul_add(Simd::splat(v[0] as f64), Simd::splat(C2) - p_hi_0);
    t[1] += p_hi_0.to_bits();
    t[0] += p_lo_0.to_bits();

    let p_hi_1 = s.mul_add(Simd::splat(v[1] as f64), Simd::splat(C1));
    let p_lo_1 = s.mul_add(Simd::splat(v[1] as f64), Simd::splat(C2) - p_hi_1);
    t[2] += p_hi_1.to_bits();
    t[1] += p_lo_1.to_bits();

    let p_hi_2 = s.mul_add(Simd::splat(v[2] as f64), Simd::splat(C1));
    let p_lo_2 = s.mul_add(Simd::splat(v[2] as f64), Simd::splat(C2) - p_hi_2);
    t[3] += p_hi_2.to_bits();
    t[2] += p_lo_2.to_bits();

    let p_hi_3 = s.mul_add(Simd::splat(v[3] as f64), Simd::splat(C1));
    let p_lo_3 = s.mul_add(Simd::splat(v[3] as f64), Simd::splat(C2) - p_hi_3);
    t[4] += p_hi_3.to_bits();
    t[3] += p_lo_3.to_bits();

    let p_hi_4 = s.mul_add(Simd::splat(v[4] as f64), Simd::splat(C1));
    let p_lo_4 = s.mul_add(Simd::splat(v[4] as f64), Simd::splat(C2) - p_hi_4);
    t[5] += p_hi_4.to_bits();
    t[4] += p_lo_4.to_bits();

    t
}

#[inline(always)]
/// Resolve the carry bits in the upper parts 12b and reduce the result to
/// within < 3p
pub fn reduce_ct_simd(red: [Simd<u64, 2>; 6]) -> [Simd<u64, 2>; 5] {
    // The lowest limb contains carries that still need to be applied.
    let mut borrow: Simd<i64, 2> = (red[0] >> 52).cast();
    let a = [red[1], red[2], red[3], red[4], red[5]];

    // To reduce Check whether the most significant bit is set
    let mask = (a[4] >> 47).bitand(Simd::splat(1)).simd_eq(Simd::splat(0));

    // Select values based on the mask: if mask lane is true, use zeros, else use
    // U52_2P
    let zeros = [Simd::splat(0); 5];
    let twop = U52_2P.map(|pi| Simd::splat(pi));
    let b: [_; 5] = array::from_fn(|i| mask.select(zeros[i], twop[i]));

    let mut c = [Simd::splat(0); 5];
    for i in 0..c.len() {
        let tmp: Simd<i64, 2> = a[i].cast::<i64>() - b[i].cast() + borrow;
        c[i] = tmp.cast().bitand(Simd::splat(MASK52));
        borrow = tmp >> 52
    }

    c
}

#[inline(always)]
pub fn reduce_ct(a: [u64; 4]) -> [u64; 4] {
    let b = [[0_u64; 4], U64_2P];
    let msb = (a[3] >> 63) & 1;
    sub(a, b[msb as usize])
}

#[inline(always)]
pub fn sub<const N: usize>(a: [u64; N], b: [u64; N]) -> [u64; N] {
    let mut borrow: i128 = 0;
    let mut c = [0; N];
    for i in 0..N {
        let tmp = a[i] as i128 - b[i] as i128 + borrow as i128;
        c[i] = tmp as u64;
        borrow = tmp >> 64
    }
    c
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
// -------------------------------------------------------------------------------------------------
#[inline(always)]
fn carrying_mul_add(a: u64, b: u64, add: u64, carry: u64) -> (u64, u64) {
    let c: u128 = a as u128 * b as u128 + carry as u128 + add as u128;
    (c as u64, (c >> 64) as u64)
}

#[cfg(test)]
mod tests {
    use {
        crate::{block_mul, block_sqr, constants, scalar_mul, scalar_sqr},
        fp_rounding::with_rounding_mode,
        primitive_types::U256,
        rand::{Rng, SeedableRng, rngs},
    };

    const OUTPUT_MAX: [u64; 4] = [
        0x783c14d81ffffffe,
        0xaf982f6f0c8d1edd,
        0x8f5f7492fcfd4f45,
        0x9f37631a3d9cbfac,
    ];

    fn mod_mul(a: U256, b: U256) -> U256 {
        let p = U256(constants::U64_P);
        let mut c = [0u64; 4];
        c.copy_from_slice(&(a.full_mul(b) % p).0[0..4]);
        U256(c)
    }

    #[test]
    fn test_block_mul() {
        let mut rng = rngs::StdRng::seed_from_u64(0);
        let p = U256(constants::U64_P);
        let r = U256(constants::U64_R);
        let r_inv = U256(constants::U64_R_INV);

        let mut s0_a_bytes = [0u8; 32];
        let mut s0_b_bytes = [0u8; 32];
        let mut v0_a_bytes = [0u8; 32];
        let mut v0_b_bytes = [0u8; 32];
        let mut v1_a_bytes = [0u8; 32];
        let mut v1_b_bytes = [0u8; 32];

        unsafe {
            with_rounding_mode((), |guard, _| {
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

                    let (s0, v0, v1) = block_mul(
                        &guard,
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
            })
        }
    }

    #[test]
    fn test_block_sqr() {
        let mut rng = rngs::StdRng::seed_from_u64(0);
        let p = U256(constants::U64_P);
        let r = U256(constants::U64_R);
        let r_inv = U256(constants::U64_R_INV);

        let mut s0_a_bytes = [0u8; 32];
        let mut v0_a_bytes = [0u8; 32];
        let mut v1_a_bytes = [0u8; 32];

        unsafe {
            with_rounding_mode((), |guard, _| {
                for _ in 0..100000 {
                    rng.fill(&mut s0_a_bytes);
                    rng.fill(&mut v0_a_bytes);
                    rng.fill(&mut v1_a_bytes);
                    let s0_a = U256::from_little_endian(&s0_a_bytes) % p;
                    let v0_a = U256::from_little_endian(&v0_a_bytes) % p;
                    let v1_a = U256::from_little_endian(&v1_a_bytes) % p;
                    let s0_a_mont = mod_mul(s0_a, r);
                    let v0_a_mont = mod_mul(v0_a, r);
                    let v1_a_mont = mod_mul(v1_a, r);

                    let (s0, v0, v1) = block_sqr(&guard, s0_a_mont.0, v0_a_mont.0, v1_a_mont.0);
                    assert!(U256(s0) < U256(OUTPUT_MAX));
                    assert!(U256(v0) < U256(OUTPUT_MAX));
                    assert!(U256(v1) < U256(OUTPUT_MAX));
                    assert_eq!(mod_mul(U256(s0), r_inv), mod_mul(s0_a, s0_a));
                    assert_eq!(mod_mul(U256(v0), r_inv), mod_mul(v0_a, v0_a));
                    assert_eq!(mod_mul(U256(v1), r_inv), mod_mul(v1_a, v1_a));
                }
            })
        }
    }

    #[test]
    fn test_scalar_mul() {
        let mut rng = rngs::StdRng::seed_from_u64(0);
        let p = U256(constants::U64_P);
        let r = U256(constants::U64_R);
        let r_inv = U256(constants::U64_R_INV);

        let mut s0_a_bytes = [0u8; 32];
        let mut s0_b_bytes = [0u8; 32];

        for _ in 0..100000 {
            rng.fill(&mut s0_a_bytes);
            rng.fill(&mut s0_b_bytes);
            let s0_a = U256::from_little_endian(&s0_a_bytes) % p;
            let s0_b = U256::from_little_endian(&s0_b_bytes) % p;
            let s0_a_mont = mod_mul(s0_a, r);
            let s0_b_mont = mod_mul(s0_b, r);

            let s0 = scalar_mul(s0_a_mont.0, s0_b_mont.0);
            assert!(U256(s0) < U256(OUTPUT_MAX));
            assert_eq!(mod_mul(U256(s0), r_inv), mod_mul(s0_a, s0_b));
        }
    }

    #[test]
    fn test_scalar_sqr() {
        let mut rng = rngs::StdRng::seed_from_u64(0);
        let p = U256(constants::U64_P);
        let r = U256(constants::U64_R);
        let r_inv = U256(constants::U64_R_INV);

        let mut s0_a_bytes = [0u8; 32];

        for _ in 0..100000 {
            rng.fill(&mut s0_a_bytes);
            let s0_a = U256::from_little_endian(&s0_a_bytes) % p;
            let s0_a_mont = mod_mul(s0_a, r);

            let s0 = scalar_sqr(s0_a_mont.0);
            assert!(U256(s0) < U256(OUTPUT_MAX));
            assert_eq!(mod_mul(U256(s0), r_inv), mod_mul(s0_a, s0_a));
        }
    }
}
