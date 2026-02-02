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
    seq_macro::seq,
    std::simd::{
        num::{SimdInt, SimdUint},
        simd_swizzle,
    },
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

/// Convert 4×64-bit to 5×51-bit limb representation.
/// Input must fit in 255 bits; no runtime checking.
#[inline(always)]
pub fn u256_to_u255(limbs: [u64; 4]) -> [u64; 5] {
    let [l0, l1, l2, l3] = limbs;
    [
        (l0) & MASK51,
        ((l0 >> 51) | (l1 << 13)) & MASK51,
        ((l1 >> 38) | (l2 << 26)) & MASK51,
        ((l2 >> 25) | (l3 << 39)) & MASK51,
        l3 >> 12 & MASK51,
    ]
}

pub fn i2f_scalar(a: u64) -> f64 {
    // This function has no target gating as we want to verify this function with
    // kani and proptest on a different platform than wasm

    // By adding 2^52 represented as float (0x1p52) -> 0x433 << 52, we align the
    // 52bit number fully in the mantissa. This can be done with a simple or. Then
    // to convert a to it's floating point number we subtract this again. This way
    // we only pay for the conversion of the lower bits and not the full 64 bits.
    let exponent = 0x433 << 52;
    let a: f64 = f64::from_bits(a | exponent);
    let b: f64 = f64::from_bits(exponent);
    a - b
}

#[inline(always)]
pub fn smult_noinit(s: u64, v: [u64; 5]) -> [Simd<i64, 2>; 6] {
    let mut t = [Simd::splat(0); 6];
    let s: Simd<f64, 2> = Simd::splat(i2f_scalar(s));

    let v01 = Simd::from_array([v[0] as f64, v[1] as f64]);
    let p_hi = fma(s, v01, Simd::splat(C1));
    let p_lo = fma(s, v01, Simd::splat(C2) - p_hi);
    t[1] += p_hi.to_bits().cast();
    t[0] += p_lo.to_bits().cast();

    let v23 = Simd::from_array([v[2] as f64, v[3] as f64]);
    let p_hi = fma(s, v23, Simd::splat(C1));
    let p_lo = fma(s, v23, Simd::splat(C2) - p_hi);
    t[3] += p_hi.to_bits().cast();
    t[2] += p_lo.to_bits().cast();

    let v45 = Simd::from_array([v[4] as f64, 0.]);
    let p_hi = fma(s, v45, Simd::splat(C1));
    let p_lo = fma(s, v45, Simd::splat(C2) - p_hi);
    t[5] += Simd::from_array([p_hi[0].to_bits() as i64, 0]);
    t[4] += Simd::from_array([p_lo[0].to_bits() as i64, 0]);

    t
}

/// Two parallel Montgomery multiplications: `(v0_a*v0_b, v1_a*v1_b)`.
/// input must fit in 2^255-1; no runtime checking
#[inline(always)]
pub fn simd_mul(v0_a: [u64; 4], v0_b: [u64; 4]) -> ([u64; 4], [u64; 4]) {
    let v0_a = u256_to_u255(v0_a);
    let v0_b = u256_to_u255(v0_b);

    let mut ts = [Simd::splat(0); 10];
    ts[0] = Simd::from_array([make_initial(1, 0), make_initial(2, 1)]);
    ts[2] = Simd::from_array([make_initial(3, 2), make_initial(4, 3)]);
    ts[4] = Simd::from_array([make_initial(10, 4), make_initial(10, 10)]);
    ts[6] = Simd::from_array([make_initial(9, 10), make_initial(8, 9)]);
    ts[8] = Simd::from_array([make_initial(7, 8), make_initial(1, 7)]);

    // Offset multiplication to have less intermediate data
    seq!(i in 0..5{
        let ai: Simd<f64, 2> = i2f(Simd::splat(v0_a[i]));
        let b01: Simd<f64, 2> = i2f(Simd::from_array([v0_b[0], v0_b[1]]));
        let p_hi = fma(ai, b01, Simd::splat(C1));
        let p_lo = fma(ai, b01, Simd::splat(C2) - p_hi);
        ts[i+1] += p_hi.to_bits().cast();
        ts[i+0] += p_lo.to_bits().cast();

        let b23: Simd<f64, 2> = i2f(Simd::from_array([v0_b[2], v0_b[3]]));
        let p_hi = fma(ai, b23, Simd::splat(C1));
        let p_lo = fma(ai, b23, Simd::splat(C2) - p_hi);
        ts[i+3] += p_hi.to_bits().cast();
        ts[i+2] += p_lo.to_bits().cast();

        let b4 = Simd::from_array([i2f_scalar(v0_b[4]),0.]);
        let p_hi = fma(ai, b4, Simd::splat(C1));
        let p_lo = fma(ai, b4, Simd::splat(C2) - p_hi);
        ts[i + 5] += p_hi.to_bits().cast();
        ts[i + 4] += p_lo.to_bits().cast();

    });

    let mut t: [i64; 4] = [0; 4];

    seq!( i in 0..2 {
        let s = i * 2;
        ts[s] += simd_swizzle!(Simd::splat(0), ts[s + 1], [0, 2]);
        ts[s + 2] += simd_swizzle!(Simd::splat(0), ts[s + 1], [3, 0]);
        t[s] = ts[s][0];
        t[s + 1] = ts[s][1];
    });

    // sign extend redundant carries
    t[1] += t[0] >> 51;
    t[2] += t[1] >> 51;
    t[3] += t[2] >> 51;

    // Lift carry into SIMD to prevent extraction
    ts[4] += Simd::from_array([t[3] >> 51, 0]);

    let r0 = smult_noinit(t[0] as u64 & MASK51, RHO_4);
    let r1 = smult_noinit(t[1] as u64 & MASK51, RHO_3);
    let r2 = smult_noinit(t[2] as u64 & MASK51, RHO_2);
    let r3 = smult_noinit(t[3] as u64 & MASK51, RHO_1);

    let mut ss = [ts[4], ts[5], ts[6], ts[7], ts[8], ts[9]];

    seq!( i in 0..6 {
        ss[i] += r0[i] + r1[i] + r2[i] + r3[i];
    });

    seq!( i in 0..2 {
        let s = i * 2;
        ss[s] += simd_swizzle!(Simd::splat(0), ss[s + 1], [0, 2]);
        ss[s + 2] += simd_swizzle!(Simd::splat(0), ss[s + 1], [3, 0]);
    });
    ss[5 - 1] += simd_swizzle!(Simd::splat(0), ss[5], [0, 2]);
    // After this point only the even ts matter

    let mut t = [0; 6];
    seq!(i in 0..3 {
        let s = i * 2;
        t[s] = ss[s][0];
        t[s + 1] = ss[s][1];
    });

    let s = [
        Simd::splat(t[0]),
        Simd::splat(t[1]),
        Simd::splat(t[2]),
        Simd::splat(t[3]),
        Simd::splat(t[4]),
        Simd::splat(t[5]),
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
            )| {
                let a: [Simd<u64,1>;_] = a.map(Simd::splat);
                let b: [Simd<u64,1>;_] = b.map(Simd::splat);
                let a = u255_to_u256_simd(a).map(|x|x[0]);
                let b = u255_to_u256_simd(b).map(|x|x[0]);
                let (ab, _bc) = simd_mul(a, b);
                let ab_ref = ark_ff_reference(a, b);
                let ab = Fr::new(BigInt(ab));
                prop_assert_eq!(ab_ref, ab, "mismatch: l = {:X}, b = {:X}", ab_ref.into_bigint(), ab.into_bigint());
        })
    }

    // #[test]
    // fn test_simd_sqr() {
    //     proptest!(|(
    //             a in limbs5_51(),
    //             b in limbs5_51(),
    //         )| {
    //             let a: [Simd<u64,1>;_] = a.map(Simd::splat);
    //             let b: [Simd<u64,1>;_] = b.map(Simd::splat);
    //             let a = u255_to_u256_simd(a).map(|x|x[0]);
    //             let b = u255_to_u256_simd(b).map(|x|x[0]);
    //             let (a2, _b2) = simd_mul(a, b, b);
    //             let (a2s, _b2s) = simd_sqr(a, b);
    //             prop_assert_eq!(a2, a2s);
    //     })
    // }

    fn limb51() -> impl Strategy<Value = u64> {
        0u64..(1u64 << 51)
    }

    fn limbs5_51() -> impl Strategy<Value = [u64; 5]> {
        prop::array::uniform5(limb51())
    }
}
