use {
    crate::{
        constants::*,
        scalar::reduce_ct,
        subarray,
        utils::{
            addv, addv_simd, carrying_mul_add, make_initial, reduce_ct_simd, smult_noinit_simd,
            transpose_simd_to_u256, transpose_u256_to_simd, u256_to_u260_shl2_simd,
            u260_to_u256_simd,
        },
    },
    core::{
        arch::aarch64::vcvtq_f64_u64,
        ops::BitAnd,
        simd::{Simd, num::SimdFloat},
    },
    fp_rounding::{RoundingGuard, Zero},
    std::simd::StdFloat,
};

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
