//! SIMD Montgomery multiplication and squaring for BN254.
//!
//! This module provides single-input Montgomery multiplication using (relaxed)
//! SIMD FMA operations. Unlike [`batched`](super::batched) which processes two
//! multiplications per call, this handles one at a time— this variant is the
//! fastest on WASM.

use {
    crate::rne::{
        constants::*,
        simd_utils::{fma, i2f, make_initial},
    },
    core::simd::{num::SimdFloat, Simd},
    seq_macro::seq,
    std::simd::{num::SimdUint, simd_swizzle},
};

/// Propagate carries/borrows from redundant limb form to normalized form.
///
/// Input `i64` limbs may have excess bits (positive = carry, negative =
/// borrow). Output `u64` limbs are normalized to exactly 51 bits, except the
/// MSB which absorbs any remaining carry and may exceed 51 bits.
#[inline(always)]
fn redundant_carry<const N: usize>(t: [i64; N]) -> [u64; N] {
    let mut borrow = 0;
    let mut res = [0; N];
    for i in 0..t.len() - 1 {
        let tmp = t[i] + borrow;
        res[i] = (tmp as u64) & MASK51;
        borrow = tmp >> 51;
    }

    res[N - 1] = (t[N - 1] + borrow) as u64;
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
        (l3 >> 12) & MASK51,
    ]
}

pub const fn i2f_scalar(a: u64) -> f64 {
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

/// Multiply a 51-bit scalar `s` by a 5×51-bit vector `v`.
///
/// Returns vector redundant SIMD and carry form. "noinit" means no FMA anchor
/// compensation is applied; the caller must initialize accumulators with
/// `make_initial` biases.
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
    t[5] += p_hi.to_bits().cast();
    t[4] += p_lo.to_bits().cast();

    t
}

/// Constant-time preparation for division by 2.
///
/// If the input is odd, adds P (which is also odd) to make it even.
/// This ensures the subsequent right-shift is exact. "ct" = constant-time.
#[inline(always)]
pub fn reduce_ct(mut a: [i64; 5]) -> [i64; 5] {
    // When input is odd, add P to make it even
    let mask = -(a[0] & 1);

    seq!( i in 0..5 {
        a[i] += U51_P[i] as i64 & mask;
    });

    // Check that final result is even
    debug_assert!(a[0] & 1 == 0);

    a
}

/// Montgomery multiplication for BN254 scalar field.
///
/// Computes `a * b * R^{-256} mod P` where R = 2^256.
///
/// # Preconditions
///
/// - Both inputs must be < 2^255 (i.e., fit in 5×51-bit limbs)
/// - Inputs should be in Montgomery form with R = 2^256
///
/// # Performance
///
/// Optimized for WASM with relaxed SIMD. Processes one multiplication at a time
/// (vs. `simd_mul` which batches two).
#[inline(always)]
pub fn mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    // # Algorithm Overview
    // Uses floating-point FMA for fast 51×51-bit multiplications via the
    // Renes-Costello-Batina technique. The algorithm proceeds in phases:
    //
    // 1. **Limb conversion**: Convert 4×64-bit inputs to 5×51-bit representation.
    //
    // 2. **Schoolbook multiplication**: Compute the 10-limb product `a × b` using
    //    FMA-based multiply-accumulate. Results are stored in "redundant SIMD form"
    //    where high/low parts of products occupy separate SIMD lanes.
    //
    // 3. **Parallel reduction**: Instead of sequential CIOS reduction, multiply the
    //    lower 4 limbs by precomputed `RHO_i = R^i mod P` constants. This converts
    //    `t[i] * 2^{51*i}` into an equivalent value in the upper limbs, allowing
    //    all reductions to proceed in parallel.
    //
    // 4. **Final Montgomery step**: Compute `m = (result[0] * -P^{-1}) mod 2^51`,
    //    then add `m * P` to cancel the lowest limb.
    //
    // 5. **Bit adjustment**: The 5×51 = 255 bit representation requires a final
    //    division by 2 (after conditional addition of P for odd results) to produce
    //    the correct R^{-256} Montgomery form.
    //
    // # Redundant Representations
    //
    // The code uses two distinct "redundant" representations:
    //
    // 1. **Redundant SIMD form**: FMA produces high/low product parts in separate
    //    SIMD vectors with misaligned lanes. E.g., `ts[k] = [limb_k_lo,
    //    limb_{k+1}_lo]` and `ts[k+1] = [limb_k_hi, limb_{k+1}_hi]`. Swizzle
    //    operations realign these so adjacent limbs occupy consecutive positions.
    //
    // 2. **Redundant limb form**: Each 51-bit limb may temporarily exceed 51 bits.
    //    The excess bits are carries (or borrows) that propagate to higher limbs.
    //    - `u64` limbs: excess bits are positive carries
    //    - `i64` limbs: excess bits may be negative, representing borrows from
    //      above

    let a = u256_to_u255(a);
    let b = u256_to_u255(b);

    let mut ts = [Simd::splat(0); 10];
    ts[0] = Simd::from_array([make_initial(1, 0), make_initial(2, 1)]);
    ts[2] = Simd::from_array([make_initial(3, 2), make_initial(4, 3)]);
    ts[4] = Simd::from_array([make_initial(10, 4), make_initial(10, 10)]);
    ts[6] = Simd::from_array([make_initial(9, 10), make_initial(8, 9)]);
    ts[8] = Simd::from_array([make_initial(7, 8), make_initial(6, 7)]);

    seq!(i in 0..5{
        let ai: Simd<f64, 2> = i2f(Simd::splat(a[i]));
        let b01: Simd<f64, 2> = i2f(Simd::from_array([b[0], b[1]]));
        let p_hi = fma(ai, b01, Simd::splat(C1));
        let p_lo = fma(ai, b01, Simd::splat(C2) - p_hi);
        ts[i+1] += p_hi.to_bits().cast();
        ts[i+0] += p_lo.to_bits().cast();

        let b23: Simd<f64, 2> = i2f(Simd::from_array([b[2], b[3]]));
        let p_hi = fma(ai, b23, Simd::splat(C1));
        let p_lo = fma(ai, b23, Simd::splat(C2) - p_hi);
        ts[i+3] += p_hi.to_bits().cast();
        ts[i+2] += p_lo.to_bits().cast();

        let b4 = Simd::from_array([i2f_scalar(b[4]),0.]);
        let p_hi = fma(ai, b4, Simd::splat(C1));
        let p_lo = fma(ai, b4, Simd::splat(C2) - p_hi);
        ts[i + 5] += p_hi.to_bits().cast();
        ts[i + 4] += p_lo.to_bits().cast();

    });

    let mut t: [i64; 4] = [0; 4];

    // Realign redundant SIMD form to scalar form for the lower 4 limbs.
    // FMA produces: ts[k] = [limb_k_lo, limb_{k+1}_lo]
    //               ts[k+1] = [limb_k_hi, limb_{k+1}_hi]
    // But limb_k_hi belongs with limb_{k+1}_lo (adjacent in the product).
    // Swizzle moves: ts[k+1][0] -> ts[k][0], ts[k+1][1] -> ts[k+2][0]
    seq!( i in 0..2 {
        let k = i * 2;
        ts[k] += simd_swizzle!(Simd::splat(0), ts[k + 1], [0, 2]);
        ts[k + 2] += simd_swizzle!(Simd::splat(0), ts[k + 1], [3, 0]);
        t[k] = ts[k][0];
        t[k + 1] = ts[k][1];
    });

    // Propagate carries/borrows through redundant limb form (i64 allows negative
    // excess)
    t[1] += t[0] >> 51;
    t[2] += t[1] >> 51;
    t[3] += t[2] >> 51;

    // Lift carry into SIMD to prevent extraction
    ts[4] += Simd::from_array([t[3] >> 51, 0]);

    // Parallel reduction: t[i] * RHO_{4-i} ≡ t[i] * 2^{51*i} * R^{-1} (mod P)
    // This replaces sequential CIOS with independent multiplications.
    let r0 = smult_noinit(t[0] as u64 & MASK51, RHO_4);
    let r1 = smult_noinit(t[1] as u64 & MASK51, RHO_3);
    let r2 = smult_noinit(t[2] as u64 & MASK51, RHO_2);
    let r3 = smult_noinit(t[3] as u64 & MASK51, RHO_1);

    let mut ss = [ts[4], ts[5], ts[6], ts[7], ts[8], ts[9]];

    seq!( i in 0..6 {
        ss[i] += r0[i] + r1[i] + r2[i] + r3[i];
    });

    // Final Montgomery reduction: m = ss[0] * (-P^{-1}) mod 2^51, then add m*P
    // to make the lowest limb zero (it gets shifted out).
    let m = (ss[0][0] as u64).wrapping_mul(U51_NP0) & MASK51;
    let mp = smult_noinit(m, U51_P);

    seq!( i in 0..6 {
        ss[i] += mp[i];
    });

    // Realign from redundant SIMD form (misaligned lanes) to aligned lanes
    seq!( i in 0..2 {
        let s = i * 2;
        ss[s] += simd_swizzle!(Simd::splat(0), ss[s + 1], [0, 2]);
        ss[s + 2] += simd_swizzle!(Simd::splat(0), ss[s + 1], [3, 0]);
    });
    ss[5 - 1] += simd_swizzle!(Simd::splat(0), ss[5], [0, 2]);

    // Extract to redundant limb form (i64 with carry/borrow in upper bits)
    let mut s: [i64; 6] = [0; 6];
    seq!(i in 0..3 {
        let k = i * 2;
        s[k] = ss[k][0];
        s[k + 1] = ss[k][1];
    });

    // Propagate carry/borrow from s[0] and discard it (absorbed by Montgomery
    // reduction)
    s[1] += s[0] >> 51;
    let s = [s[1], s[2], s[3], s[4], s[5]];

    // Bit adjustment: 5×51 = 255 bits, but we need R^{-256}. Divide by 2 via
    // reduce_ct (adds P if odd) followed by right-shift in u255_to_u256_shr_1.
    let reduced = reduce_ct(s);
    let reduced = redundant_carry(reduced);
    let u256_result = u255_to_u256_shr_1(reduced);
    u256_result
}

/// Convert 5×51-bit to 4×64-bit with simultaneous division by 2.
#[inline(always)]
pub fn u255_to_u256_shr_1(limbs: [u64; 5]) -> [u64; 4] {
    let [l0, l1, l2, l3, l4] = limbs;
    [
        (l0 >> 1) | (l1 << 50),
        (l1 >> 14) | (l2 << 37),
        (l2 >> 27) | (l3 << 24),
        (l3 >> 40) | (l4 << 11),
    ]
}

/// Montgomery squaring: a²
///
/// Input and output are in Montgomery form R=256.
///
/// Precondition:
/// - a < 2^255; no runtime check.
#[inline(always)]
pub fn sqr(a: [u64; 4]) -> [u64; 4] {
    mul(a, a)
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::test_utils::{ark_ff_reference, limbs5_51},
        ark_bn254::Fr,
        ark_ff::{BigInt, PrimeField},
        proptest::{prop_assert_eq, proptest},
    };

    #[test]
    fn test_simd_mul() {
        proptest!(|(
                a in limbs5_51(),
                b in limbs5_51(),
            )| {
                let a = u255_to_u256(a);
                let b = u255_to_u256(b);
                let ab = mul(a, b);
                let ab_ref = ark_ff_reference(a, b);
                let ab = Fr::new(BigInt(ab));
                prop_assert_eq!(ab_ref, ab, "mismatch: l = {:X}, b = {:X}", ab_ref.into_bigint(), ab.into_bigint());
        })
    }

    #[test]
    fn test_simd_sqr() {
        proptest!(|(
                a in limbs5_51(),
            )| {
                let a = u255_to_u256(a);
                prop_assert_eq!(mul(a,a), sqr(a));
        })
    }

    #[inline(always)]
    pub fn u255_to_u256(limbs: [u64; 5]) -> [u64; 4] {
        let [l0, l1, l2, l3, l4] = limbs;
        [
            l0 | (l1 << 51),
            (l1 >> 13) | (l2 << 38),
            (l2 >> 26) | (l3 << 25),
            (l3 >> 39) | (l4 << 12),
        ]
    }
}
