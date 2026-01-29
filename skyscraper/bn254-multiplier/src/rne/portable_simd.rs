//! Portable SIMD Montgomery multiplication and squaring.
//!
//! Processes two independent field multiplications in parallel using 2-lane
//! SIMD.

use {
    crate::rne::{
        constants::*,
        simd_utils::{
            addv_simd, fma, i2f, make_initial, reduce_ct_simd, smult_noinit_simd,
            transpose_simd_to_u256, transpose_u256_to_simd, u255_to_u256_shr_1_simd,
            u256_to_u255_simd,
        },
    },
    core::{
        ops::BitAnd,
        simd::{num::SimdFloat, Simd},
    },
    std::simd::num::{SimdInt, SimdUint},
};

/// Two parallel Montgomery squarings: `(v0², v1²)`.
/// input must fit in 2^255-1; no runtime checking
#[inline]
pub fn simd_sqr(v0_a: [u64; 4], v1_a: [u64; 4]) -> ([u64; 4], [u64; 4]) {
    let v0_a = u256_to_u255_simd(transpose_u256_to_simd([v0_a, v1_a]));

    let mut t: [Simd<i64, 2>; 10] = [Simd::splat(0); 10];

    for i in 0..5 {
        let avi: Simd<f64, 2> = i2f(v0_a[i]);
        for j in (i + 1)..5 {
            let bvj: Simd<f64, 2> = i2f(v0_a[j]);
            let p_hi = fma(avi, bvj, Simd::splat(C1));
            let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
            t[i + j + 1] += p_hi.to_bits().cast();
            t[i + j] += p_lo.to_bits().cast();
        }
    }

    // Most shifting operations are more expensive addition thus for multiplying by
    // 2 we use addition.
    for i in 1..=8 {
        t[i] += t[i];
    }

    for i in 0..5 {
        let avi: Simd<f64, 2> = i2f(v0_a[i]);
        let p_hi = fma(avi, avi, Simd::splat(C1));
        let p_lo = fma(avi, avi, Simd::splat(C2) - p_hi);
        t[i + i + 1] += p_hi.to_bits().cast();
        t[i + i] += p_lo.to_bits().cast();
    }

    t[0] += Simd::splat(make_initial(1, 0));
    t[9] += Simd::splat(make_initial(0, 6));
    t[1] += Simd::splat(make_initial(2, 1));
    t[8] += Simd::splat(make_initial(6, 7));
    t[2] += Simd::splat(make_initial(3, 2));
    t[7] += Simd::splat(make_initial(7, 8));
    t[3] += Simd::splat(make_initial(4, 3));
    t[6] += Simd::splat(make_initial(8, 9));
    t[4] += Simd::splat(make_initial(10, 4));
    t[5] += Simd::splat(make_initial(9, 10));

    t[1] += t[0] >> 51;
    t[2] += t[1] >> 51;
    t[3] += t[2] >> 51;
    t[4] += t[3] >> 51;

    let r0 = smult_noinit_simd(t[0].cast().bitand(Simd::splat(MASK51)), RHO_4);
    let r1 = smult_noinit_simd(t[1].cast().bitand(Simd::splat(MASK51)), RHO_3);
    let r2 = smult_noinit_simd(t[2].cast().bitand(Simd::splat(MASK51)), RHO_2);
    let r3 = smult_noinit_simd(t[3].cast().bitand(Simd::splat(MASK51)), RHO_1);

    let s = [
        r0[0] + r1[0] + r2[0] + r3[0] + t[4],
        r0[1] + r1[1] + r2[1] + r3[1] + t[5],
        r0[2] + r1[2] + r2[2] + r3[2] + t[6],
        r0[3] + r1[3] + r2[3] + r3[3] + t[7],
        r0[4] + r1[4] + r2[4] + r3[4] + t[8],
        r0[5] + r1[5] + r2[5] + r3[5] + t[9],
    ];

    // The upper bits of s will not affect the lower 51 bits of the product and
    // therefore we only have to bitmask once.
    let m = (s[0].cast() * Simd::splat(U51_NP0)).bitand(Simd::splat(MASK51));
    let mp = smult_noinit_simd(m, U51_P);

    let mut addi = addv_simd(s, mp);
    // Apply carries before dropping the last limb
    addi[1] += addi[0] >> 51;
    let addi = [addi[1], addi[2], addi[3], addi[4], addi[5]];

    // 1 bit reduction to go from R^-255 to R^-256. reduce_ct does the preparation
    // and the final shift is done as part of the conversion back to u256
    let reduced = reduce_ct_simd(addi);
    let reduced = redundant_carry(reduced);
    let u256_result = u255_to_u256_shr_1_simd(reduced);
    let v = transpose_simd_to_u256(u256_result);
    (v[0], v[1])
}

/// Move redundant carries from lower limbs to the higher limbs such that all
/// limbs except the last one is 51 bits. The most significant limb can be
/// larger than 51 bits as the input can be bigger 2^255-1.
#[inline(always)]
fn redundant_carry<const N: usize, const L: usize>(t: [Simd<i64, L>; N]) -> [Simd<u64, L>; N]
where
    std::simd::LaneCount<L>: std::simd::SupportedLaneCount,
{
    let mut borrow = Simd::splat(0);
    let mut res = [Simd::splat(0); N];
    for i in 0..t.len() - 1 {
        let tmp = t[i] + borrow;
        res[i] = (tmp.cast()).bitand(Simd::splat(MASK51));
        borrow = tmp >> 51;
    }

    res[N - 1] = (t[N - 1] + borrow).cast();
    res
}

/// Two parallel Montgomery multiplications: `(v0_a*v0_b, v1_a*v1_b)`.
/// input must fit in 2^255-1; no runtime checking
#[inline(always)]
pub fn simd_mul(
    v0_a: [u64; 4],
    v0_b: [u64; 4],
    v1_a: [u64; 4],
    v1_b: [u64; 4],
) -> ([u64; 4], [u64; 4]) {
    let v0_a = u256_to_u255_simd(transpose_u256_to_simd([v0_a, v1_a]));
    let v0_b = u256_to_u255_simd(transpose_u256_to_simd([v0_b, v1_b]));

    let mut t: [Simd<_, 2>; 10] = [Simd::splat(0); 10];
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

    let avi: Simd<f64, 2> = i2f(v0_a[0]);
    let bvj: Simd<f64, 2> = i2f(v0_b[0]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[1] += p_hi.to_bits().cast();
    t[0] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[1]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[1 + 1] += p_hi.to_bits().cast();
    t[1] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[2]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[2 + 1] += p_hi.to_bits().cast();
    t[2] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[3]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[3 + 1] += p_hi.to_bits().cast();
    t[3] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[4]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[4 + 1] += p_hi.to_bits().cast();
    t[4] += p_lo.to_bits().cast();

    let avi: Simd<f64, 2> = i2f(v0_a[1]);
    let bvj: Simd<f64, 2> = i2f(v0_b[0]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[1 + 1] += p_hi.to_bits().cast();
    t[1] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[1]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[1 + 1 + 1] += p_hi.to_bits().cast();
    t[1 + 1] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[2]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[1 + 2 + 1] += p_hi.to_bits().cast();
    t[1 + 2] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[3]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[1 + 3 + 1] += p_hi.to_bits().cast();
    t[1 + 3] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[4]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[1 + 4 + 1] += p_hi.to_bits().cast();
    t[1 + 4] += p_lo.to_bits().cast();

    let avi: Simd<f64, 2> = i2f(v0_a[2]);
    let bvj: Simd<f64, 2> = i2f(v0_b[0]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[2 + 1] += p_hi.to_bits().cast();
    t[2] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[1]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[2 + 1 + 1] += p_hi.to_bits().cast();
    t[2 + 1] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[2]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[2 + 2 + 1] += p_hi.to_bits().cast();
    t[2 + 2] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[3]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[2 + 3 + 1] += p_hi.to_bits().cast();
    t[2 + 3] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[4]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[2 + 4 + 1] += p_hi.to_bits().cast();
    t[2 + 4] += p_lo.to_bits().cast();

    let avi: Simd<f64, 2> = i2f(v0_a[3]);
    let bvj: Simd<f64, 2> = i2f(v0_b[0]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[3 + 1] += p_hi.to_bits().cast();
    t[3] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[1]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[3 + 1 + 1] += p_hi.to_bits().cast();
    t[3 + 1] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[2]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[3 + 2 + 1] += p_hi.to_bits().cast();
    t[3 + 2] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[3]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[3 + 3 + 1] += p_hi.to_bits().cast();
    t[3 + 3] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[4]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[3 + 4 + 1] += p_hi.to_bits().cast();
    t[3 + 4] += p_lo.to_bits().cast();

    let avi: Simd<f64, 2> = i2f(v0_a[4]);
    let bvj: Simd<f64, 2> = i2f(v0_b[0]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[4 + 1] += p_hi.to_bits().cast();
    t[4] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[1]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[4 + 1 + 1] += p_hi.to_bits().cast();
    t[4 + 1] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[2]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[4 + 2 + 1] += p_hi.to_bits().cast();
    t[4 + 2] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[3]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[4 + 3 + 1] += p_hi.to_bits().cast();
    t[4 + 3] += p_lo.to_bits().cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[4]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[4 + 4 + 1] += p_hi.to_bits().cast();
    t[4 + 4] += p_lo.to_bits().cast();

    // sign extend redundant carries
    t[1] += t[0] >> 51;
    t[2] += t[1] >> 51;
    t[3] += t[2] >> 51;
    t[4] += t[3] >> 51;

    let r0 = smult_noinit_simd(t[0].cast().bitand(Simd::splat(MASK51)), RHO_4);
    let r1 = smult_noinit_simd(t[1].cast().bitand(Simd::splat(MASK51)), RHO_3);
    let r2 = smult_noinit_simd(t[2].cast().bitand(Simd::splat(MASK51)), RHO_2);
    let r3 = smult_noinit_simd(t[3].cast().bitand(Simd::splat(MASK51)), RHO_1);

    let s = [
        r0[0] + r1[0] + r2[0] + r3[0] + t[4],
        r0[1] + r1[1] + r2[1] + r3[1] + t[5],
        r0[2] + r1[2] + r2[2] + r3[2] + t[6],
        r0[3] + r1[3] + r2[3] + r3[3] + t[7],
        r0[4] + r1[4] + r2[4] + r3[4] + t[8],
        r0[5] + r1[5] + r2[5] + r3[5] + t[9],
    ];

    let m = (s[0].cast() * Simd::splat(U51_NP0)).bitand(Simd::splat(MASK51));
    let mp = smult_noinit_simd(m, U51_P);

    let mut addi = addv_simd(s, mp);
    addi[1] += addi[0] >> 51;
    let addi = [addi[1], addi[2], addi[3], addi[4], addi[5]];

    // 1 bit reduction to go from R^-255 to R^-256. reduce_ct does the preparation
    // and the final shift is done as part of the conversion back to u256
    let reduced = reduce_ct_simd(addi);
    let reduced = redundant_carry(reduced);
    let u256_result = u255_to_u256_shr_1_simd(reduced);
    let v = transpose_simd_to_u256(u256_result);
    (v[0], v[1])
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{rne::simd_utils::u255_to_u256_simd, test_utils::ark_ff_reference},
        ark_bn254::Fr,
        ark_ff::{BigInt, PrimeField},
        proptest::{
            prelude::{prop, Strategy},
            prop_assert_eq, proptest,
        },
    };

    #[test]
    fn test_simd_mul() {
        proptest!(|(
                a in limbs5_51(),
                b in limbs5_51(),
                c in limbs5_51(),
            )| {
                let a: [Simd<u64,1>;_] = a.map(Simd::splat);
                let b: [Simd<u64,1>;_] = b.map(Simd::splat);
                let c: [Simd<u64,1>;_] = c.map(Simd::splat);
                let a = u255_to_u256_simd(a).map(|x|x[0]);
                let b = u255_to_u256_simd(b).map(|x|x[0]);
                let c = u255_to_u256_simd(c).map(|x|x[0]);
                let (ab, bc) = simd_mul(a, b,b,c);
                let ab_ref = ark_ff_reference(a, b);
                let bc_ref = ark_ff_reference(b, c);
                let ab = Fr::new(BigInt(ab));
                let bc = Fr::new(BigInt(bc));
                prop_assert_eq!(ab_ref, ab, "mismatch: l = {:X}, b = {:X}", ab_ref.into_bigint(), ab.into_bigint());
                prop_assert_eq!(bc_ref, bc, "mismatch: l = {:X}, b = {:X}", bc_ref.into_bigint(), bc.into_bigint());
        })
    }

    #[test]
    fn test_simd_sqr() {
        proptest!(|(
                a in limbs5_51(),
                b in limbs5_51(),
            )| {
                let a: [Simd<u64,1>;_] = a.map(Simd::splat);
                let b: [Simd<u64,1>;_] = b.map(Simd::splat);
                let a = u255_to_u256_simd(a).map(|x|x[0]);
                let b = u255_to_u256_simd(b).map(|x|x[0]);
                let (a2, _b2) = simd_mul(a, a, b, b);
                let (a2s, _b2s) = simd_sqr(a, b);
                prop_assert_eq!(a2, a2s);
        })
    }

    fn limb51() -> impl Strategy<Value = u64> {
        0u64..(1u64 << 51)
    }

    fn limbs5_51() -> impl Strategy<Value = [u64; 5]> {
        prop::array::uniform5(limb51())
    }
}
