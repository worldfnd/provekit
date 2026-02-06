//! SIMD utilities for RNE Montgomery multiplication.

use {
    crate::rne::constants::{C1, C2, C3, MASK51, U51_P},
    core::{
        array,
        ops::BitAnd,
        simd::{
            cmp::SimdPartialEq,
            num::{SimdFloat, SimdInt, SimdUint},
            Simd,
        },
    },
    std::simd::{LaneCount, SupportedLaneCount},
};
#[inline(always)]
/// On WASM there is no single specialised instruction to cast an integer to a
/// float. Since we are only interested in 52 bits, we can emulate it with fewer
/// instructions.
///
/// Warning: due to Rust's limitations this can not be a const function.
/// Therefore check your dependency path as this will not be optimised out.
pub fn i2f<const N: usize>(a: Simd<u64, N>) -> Simd<f64, N>
where
    LaneCount<N>: SupportedLaneCount,
{
    // This function has no target gating as we want to verify this function with
    // kani and proptest on a different platform than wasm

    // By adding 2^52 represented as float (0x1p52) -> 0x433 << 52, we align the
    // 52bit number fully in the mantissa. This can be done with a simple or. Then
    // to convert a to it's floating point number we subtract this again. This way
    // we only pay for the conversion of the lower bits and not the full 64 bits.
    let exponent = Simd::splat(0x433 << 52);
    let a: Simd<f64, _> = Simd::<f64, N>::from_bits(a | exponent);
    let b: Simd<f64, _> = Simd::<f64, N>::from_bits(exponent);
    a - b
}

/// Fused multiply-add: `a * b + c`.
#[inline(always)]
pub fn fma(a: Simd<f64, 2>, b: Simd<f64, 2>, c: Simd<f64, 2>) -> Simd<f64, 2> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::simd::StdFloat;

        a.mul_add(b, c)
    }
    #[cfg(target_arch = "wasm32")]
    {
        use core::arch::wasm32::*;
        f64x2_relaxed_madd(a.into(), b.into(), c.into()).into()
    }
}

/// Computes bias compensation for accumulator limbs.
///
/// - `low_count`: number of p_lo contributions
/// - `high_count`: number of p_hi contributions
#[inline(always)]
pub const fn make_initial(low_count: u64, high_count: u64) -> i64 {
    let val = high_count
        .wrapping_mul(C1.to_bits())
        .wrapping_add(low_count.wrapping_mul(C3.to_bits()));
    -(val as i64)
}

/// Transpose two 4-limb values into 4 SIMD vectors.
#[inline(always)]
pub fn transpose_u256_to_simd(limbs: [[u64; 4]; 2]) -> [Simd<u64, 2>; 4] {
    [
        Simd::from_array([limbs[0][0], limbs[1][0]]),
        Simd::from_array([limbs[0][1], limbs[1][1]]),
        Simd::from_array([limbs[0][2], limbs[1][2]]),
        Simd::from_array([limbs[0][3], limbs[1][3]]),
    ]
}

/// Transpose 4 SIMD vectors back to two 4-limb values.
#[inline(always)]
pub fn transpose_simd_to_u256(limbs: [Simd<u64, 2>; 4]) -> [[u64; 4]; 2] {
    let tmp0 = limbs[0].to_array();
    let tmp1 = limbs[1].to_array();
    let tmp2 = limbs[2].to_array();
    let tmp3 = limbs[3].to_array();
    [[tmp0[0], tmp1[0], tmp2[0], tmp3[0]], [
        tmp0[1], tmp1[1], tmp2[1], tmp3[1],
    ]]
}

/// Convert 4×64-bit to 5×51-bit limb representation.
/// Input must fit in 255 bits; no runtime checking.
#[inline(always)]
pub fn u256_to_u255_simd<const N: usize>(limbs: [Simd<u64, N>; 4]) -> [Simd<u64, N>; 5]
where
    LaneCount<N>: SupportedLaneCount,
{
    for lane in 0..N {
        debug_assert!(limbs[3][lane] & (1 << 63) == 0);
    }

    let [l0, l1, l2, l3] = limbs;
    [
        (l0) & Simd::splat(MASK51),
        ((l0 >> 51) | (l1 << 13)) & Simd::splat(MASK51),
        ((l1 >> 38) | (l2 << 26)) & Simd::splat(MASK51),
        ((l2 >> 25) | (l3 << 39)) & Simd::splat(MASK51),
        l3 >> 12 & Simd::splat(MASK51),
    ]
}

/// Convert 5×51-bit back to 4×64-bit limb representation.
#[inline(always)]
pub fn u255_to_u256_simd<const N: usize>(limbs: [Simd<u64, N>; 5]) -> [Simd<u64, N>; 4]
where
    LaneCount<N>: SupportedLaneCount,
{
    let [l0, l1, l2, l3, l4] = limbs;
    [
        l0 | (l1 << 51),
        (l1 >> 13) | (l2 << 38),
        (l2 >> 26) | (l3 << 25),
        (l3 >> 39) | (l4 << 12),
    ]
}

/// Convert 5×51-bit to 4×64-bit with simultaneous division by 2.
#[inline(always)]
pub fn u255_to_u256_shr_1_simd<const N: usize>(limbs: [Simd<u64, N>; 5]) -> [Simd<u64, N>; 4]
where
    LaneCount<N>: SupportedLaneCount,
{
    let [l0, l1, l2, l3, l4] = limbs;
    [
        (l0 >> 1) | (l1 << 50),
        (l1 >> 14) | (l2 << 37),
        (l2 >> 27) | (l3 << 24),
        (l3 >> 40) | (l4 << 11),
    ]
}

/// Multiply SIMD scalar by 5-limb constant using FMA splitting.
/// Returns 6-limb result in redundant signed form.
#[inline(always)]
pub fn smult_noinit_simd(s: Simd<u64, 2>, v: [u64; 5]) -> [Simd<i64, 2>; 6] {
    let mut t = [Simd::splat(0); 6];
    let s: Simd<f64, 2> = i2f(s);

    let p_hi_0 = fma(s, Simd::splat(v[0] as f64), Simd::splat(C1));
    let p_lo_0 = fma(s, Simd::splat(v[0] as f64), Simd::splat(C2) - p_hi_0);
    t[1] += p_hi_0.to_bits().cast();
    t[0] += p_lo_0.to_bits().cast();

    let p_hi_1 = fma(s, Simd::splat(v[1] as f64), Simd::splat(C1));
    let p_lo_1 = fma(s, Simd::splat(v[1] as f64), Simd::splat(C2) - p_hi_1);
    t[2] += p_hi_1.to_bits().cast();
    t[1] += p_lo_1.to_bits().cast();

    let p_hi_2 = fma(s, Simd::splat(v[2] as f64), Simd::splat(C1));
    let p_lo_2 = fma(s, Simd::splat(v[2] as f64), Simd::splat(C2) - p_hi_2);
    t[3] += p_hi_2.to_bits().cast();
    t[2] += p_lo_2.to_bits().cast();

    let p_hi_3 = fma(s, Simd::splat(v[3] as f64), Simd::splat(C1));
    let p_lo_3 = fma(s, Simd::splat(v[3] as f64), Simd::splat(C2) - p_hi_3);
    t[4] += p_hi_3.to_bits().cast();
    t[3] += p_lo_3.to_bits().cast();

    let p_hi_4 = fma(s, Simd::splat(v[4] as f64), Simd::splat(C1));
    let p_lo_4 = fma(s, Simd::splat(v[4] as f64), Simd::splat(C2) - p_hi_4);
    t[5] += p_hi_4.to_bits().cast();
    t[4] += p_lo_4.to_bits().cast();

    t
}

/// Constant-time conditional add of p to prepare for final bit reduction by
/// making the result even.
#[inline(always)]
pub fn reduce_ct_simd(a: [Simd<i64, 2>; 5]) -> [Simd<i64, 2>; 5] {
    let mut c = [Simd::splat(0); 5];
    let tmp = a[0];

    // To reduce Check whether the least significant bit is set
    let mask = (tmp).bitand(Simd::splat(1)).simd_eq(Simd::splat(1));

    // Select values based on the mask: if mask lane is true, add p, else add
    // zero
    let zeros = [Simd::splat(0); 5];
    let p = U51_P.map(|x| Simd::splat(x as i64));
    let b: [_; 5] = array::from_fn(|i| mask.select(p[i], zeros[i]));

    for i in 0..c.len() {
        c[i] = a[i] + b[i];
    }

    // Check that final result is even
    debug_assert!(c[0][0] & 1 == 0);
    debug_assert!(c[0][1] & 1 == 0);

    c
}

/// Element-wise vector addition in redundant form.
#[inline(always)]
pub fn addv_simd<const N: usize>(
    va: [Simd<i64, 2>; N],
    vb: [Simd<i64, 2>; N],
) -> [Simd<i64, 2>; N] {
    let mut vc = [Simd::splat(0); N];
    for i in 0..va.len() {
        vc[i] = va[i].cast() + vb[i];
    }
    vc
}

#[cfg(kani)]
mod tests {
    use {
        crate::rne::simd_utils::{i2f, u255_to_u256_simd, u256_to_u255_simd},
        std::simd::Simd,
    };

    #[kani::proof]
    fn u256_to_u255_kani_roundtrip() {
        let u: [u64; 4] = [
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any::<u64>() & 0x7fffffffffffffff,
        ];
        let u255 = u256_to_u255_simd::<1>(u.map(Simd::splat));
        let roundtrip = u255_to_u256_simd::<1>(u255).map(|v| v[0]);
        assert_eq!(u, roundtrip)
    }

    /// Verify that i2f correctly converts integers in the valid range [0,
    /// 2^52).
    #[kani::proof]
    fn i2f_kani_correctness() {
        let val: u64 = kani::any();
        kani::assume(val < (1u64 << 52));

        let result = i2f(Simd::from_array([val]));

        assert_eq!(result[0], val as f64);
    }
}
