use {
    crate::{
        constants_wasm::*,
        simd_utils_wasm::{
            addv_simd, fma, i2f, make_initial, reduce_ct_simd, smult_noinit_simd,
            transpose_simd_to_u256, transpose_u256_to_simd, u255_to_u256_shr_1_simd,
            u255_to_u256_simd, u256_to_u255_simd,
        },
    },
    core::{
        ops::BitAnd,
        simd::{num::SimdFloat, Simd},
    },
    std::simd::{
        num::{SimdInt, SimdUint},
        LaneCount, SupportedLaneCount,
    },
};

#[inline(always)]
pub fn single_mul(a: u64, b: u64) -> (i64, i64) {
    let avi: Simd<f64, 2> = i2f(Simd::splat(a));
    let bvj: Simd<f64, 2> = i2f(Simd::splat(b));
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    (p_lo.to_bits().cast()[0], p_hi.to_bits().cast()[0])
}

#[inline(always)]
/// i64 signifies redundant carry form
/// t initialise with right for multiplication test
/// compare with school multiplication on 51 bits. This does not require having
/// to move over carries
fn multimul(t: &mut [Simd<i64, 2>; 10], v0_a: [Simd<u64, 2>; 5], v0_b: [Simd<u64, 2>; 5]) {
    let avi: Simd<f64, 2> = i2f(v0_a[0]);
    let bvj: Simd<f64, 2> = i2f(v0_b[0]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[0] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[1]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[1 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[1] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[2]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[2 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[2] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[3]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[3 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[3] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[4]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[4 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[4] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();

    let avi: Simd<f64, 2> = i2f(v0_a[1]);
    let bvj: Simd<f64, 2> = i2f(v0_b[0]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[1 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[1] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[1]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[1 + 1 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[1 + 1] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[2]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[1 + 2 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[1 + 2] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[3]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[1 + 3 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[1 + 3] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[4]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[1 + 4 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[1 + 4] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();

    let avi: Simd<f64, 2> = i2f(v0_a[2]);
    let bvj: Simd<f64, 2> = i2f(v0_b[0]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[2 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[2] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[1]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[2 + 1 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[2 + 1] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[2]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[2 + 2 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[2 + 2] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[3]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[2 + 3 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[2 + 3] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[4]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[2 + 4 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[2 + 4] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();

    let avi: Simd<f64, 2> = i2f(v0_a[3]);
    let bvj: Simd<f64, 2> = i2f(v0_b[0]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[3 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[3] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[1]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[3 + 1 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[3 + 1] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[2]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[3 + 2 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[3 + 2] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[3]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[3 + 3 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[3 + 3] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[4]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[3 + 4 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[3 + 4] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();

    let avi: Simd<f64, 2> = i2f(v0_a[4]);
    let bvj: Simd<f64, 2> = i2f(v0_b[0]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[4 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[4] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[1]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[4 + 1 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[4 + 1] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[2]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[4 + 2 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[4 + 2] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[3]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[4 + 3 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[4 + 3] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
    let bvj: Simd<f64, 2> = i2f(v0_b[4]);
    let p_hi = fma(avi, bvj, Simd::splat(C1));
    let p_lo = fma(avi, bvj, Simd::splat(C2) - p_hi);
    t[4 + 4 + 1] += (p_hi.to_bits() - Simd::splat(C1).to_bits()).cast();
    t[4 + 4] += (p_lo.to_bits() - Simd::splat(C3).to_bits()).cast();
}

fn redundant_carry<const N: usize>(t: [Simd<i64, 2>; N]) -> [Simd<u64, 2>; N] {
    let mut borrow = Simd::splat(0);
    let mut res = [Simd::splat(0); N];
    for (i, x) in t.into_iter().enumerate() {
        let tmp = x + borrow;
        res[i] = (tmp.cast()).bitand(Simd::splat(MASK51));
        borrow = tmp >> 51;
    }
    debug_assert!(borrow == Simd::splat(0));
    res
}

fn redundant_carry_excess<const N: usize>(t: [Simd<i64, 2>; N]) -> [Simd<u64, 2>; N] {
    let mut borrow = Simd::splat(0);
    let mut res = [Simd::splat(0); N];
    for (i, x) in t.into_iter().enumerate() {
        let tmp = x + borrow;
        res[i] = (tmp.cast()).bitand(Simd::splat(MASK51));
        borrow = tmp >> 51;
    }
    // Check whether borrow is not negative.
    debug_assert!(borrow >= Simd::splat(0));
    res[N - 1] = (borrow << 51).cast() | res[N - 1];
    res
}

fn redundant_carry_u64_exess<const N: usize>(t: [Simd<u64, 2>; N]) -> [Simd<u64, 2>; N] {
    let mut carry = Simd::splat(0);
    let mut res = [Simd::splat(0); N];
    for (i, x) in t.into_iter().enumerate() {
        let tmp = x + carry;
        res[i] = (tmp.cast()).bitand(Simd::splat(MASK51));
        carry = tmp >> 51;
    }
    res[N - 1] = (carry << 51) | res[N - 1];
    // debug_assert!(carry == Simd::splat(0));
    res
}

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
    // t[0] = Simd::splat(make_initial(1, 0));
    // t[9] = Simd::splat(make_initial(0, 6));
    // t[1] = Simd::splat(make_initial(2, 1));
    // t[8] = Simd::splat(make_initial(6, 7));
    // t[2] = Simd::splat(make_initial(3, 2));
    // t[7] = Simd::splat(make_initial(7, 8));
    // t[3] = Simd::splat(make_initial(4, 3));
    // t[6] = Simd::splat(make_initial(8, 9));
    // t[4] = Simd::splat(make_initial(10, 4));
    // t[5] = Simd::splat(make_initial(9, 10));

    multimul(&mut t, v0_a, v0_b);

    // sign extend redundant carries
    // t[1] += t[0] >> 51;
    // t[2] += t[1] >> 51;
    // t[3] += t[2] >> 51;
    // t[4] += t[3] >> 51;
    let t = redundant_carry(t);

    // lower 51 bits will have the right value as the carry part is either 0 or a
    // multiple of -2^51 -> which prevents carry bits to leak into the lower part.
    let r0 = smult_noinit_simd(t[0], RHO_4);
    let r0 = redundant_carry(r0);
    let r1 = smult_noinit_simd(t[1], RHO_3);
    let r1 = redundant_carry(r1);
    let r2 = smult_noinit_simd(t[2], RHO_2);
    let r2 = redundant_carry(r2);
    let r3 = smult_noinit_simd(t[3], RHO_1);
    let r3 = redundant_carry(r3);

    let s = [
        r0[0] + r1[0] + r2[0] + r3[0] + t[4],
        r0[1] + r1[1] + r2[1] + r3[1] + t[5],
        r0[2] + r1[2] + r2[2] + r3[2] + t[6],
        r0[3] + r1[3] + r2[3] + r3[3] + t[7],
        r0[4] + r1[4] + r2[4] + r3[4] + t[8],
        r0[5] + r1[5] + r2[5] + r3[5] + t[9],
    ];

    // The upper bits of s will not affect the lower 51 bits of the product so we
    // defer the and'ing.
    let m = (s[0] * Simd::splat(U51_NP0))
        .cast()
        .bitand(Simd::splat(MASK51));
    let mp = smult_noinit_simd(m, U51_P);

    let addi = redundant_carry_excess(addv_simd(s, mp));
    let reduced = reduce_ct_simd(addi);
    let reduced = redundant_carry_u64_exess(reduced);
    let u256_result = u255_to_u256_shr_1_simd(reduced);
    let v = transpose_simd_to_u256(u256_result);
    (v[0], v[1])
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::test_utils::{ark_ff_reference, safe_bn254_montgomery_input},
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
                mut a in limbs5_51(),
                mut b in limbs5_51(),
                // c in limbs5_51(),
            )| {
                let a: [Simd<u64,1>;_] = a.map(Simd::splat);
                let b: [Simd<u64,1>;_] = b.map(Simd::splat);
                let a = u255_to_u256_simd(a).map(|x|x[0]);
                let b = u255_to_u256_simd(b).map(|x|x[0]);
                let (ab, _bc) = simd_mul(a, b,a,b);
                let ab_ref = ark_ff_reference(a, b);
                // let bc_ref = ark_ff_reference(b, c);
                let ab = Fr::new(BigInt(ab));
                // let bc = Fr::new(BigInt(bc));
                prop_assert_eq!(ab_ref, ab, "mismatch: l = {:X}, b = {:X}", ab_ref.into_bigint(), ab.into_bigint());
        })
    }

    fn limb51() -> impl Strategy<Value = u64> {
        // Either of these is fine:
        // 1) Range
        0u64..(1u64 << 51)

        // 2) Or mask (sometimes faster)
        // any::<u64>().prop_map(|x| x & LIMB_MASK)
    }

    fn limbs5_51() -> impl Strategy<Value = [u64; 5]> {
        prop::array::uniform5(limb51())
    }

    fn school_mul(ax: [u64; 5], bx: [u64; 5]) -> [u64; 10] {
        let mut t = [0; 10];
        for (ai, a) in ax.into_iter().enumerate() {
            for (bi, b) in bx.into_iter().enumerate() {
                let (lo, hi) = a.widening_mul(b);
                let hi = hi << 13 | lo >> 51;
                let lo = lo & MASK51;
                t[ai + bi] += lo;
                t[ai + bi + 1] += hi;
            }
        }

        let mut carry = 0;
        let mut res = [0; 10];

        for (i, r) in t.into_iter().enumerate() {
            let tmp = r + carry;
            res[i] = tmp & MASK51;
            carry = tmp >> 51;
        }
        res
    }

    fn init_t() -> [i64; 10] {
        let mut count: [(u64, u64); _] = [(0, 0); 10];
        for ai in 0..5 {
            for bi in 0..5 {
                count[ai + bi].0 += 1;
                count[ai + bi + 1].1 += 1;
            }
        }

        let res = count.map(|(lo, hi)| make_initial(lo, hi));

        res
    }

    fn redundant_carry(t: [i64; 10]) -> [u64; 10] {
        let mut borrow: i64 = 0;
        let mut res = [0; 10];
        for (i, x) in t.into_iter().enumerate() {
            let tmp = x + borrow;
            res[i] = tmp as u64 & MASK51;
            borrow = tmp >> 51;
        }
        debug_assert!(borrow == 0);
        res
    }

    #[test]
    fn redundant_form_multi_mul() {
        proptest!(|(a in limbs5_51(), b in limbs5_51())|{
            let v0_a = a.map(Simd::splat);
            let v0_b = b.map(Simd::splat);
            let mut t: [Simd<_,_>;_] = [Simd::splat(0);10];
            // let mut t = init_t().map(Simd::splat);
            multimul(&mut t, v0_a, v0_b);
            let school = school_mul(a,b);
            let fp = redundant_carry(t.map(|x| x[0]));

            prop_assert_eq!(school, fp)

        })
    }

    #[test]
    fn single_mul_test() {
        proptest!(|(a in limb51(), b in limb51())|{
            let (lo,hi) = single_mul(a, b);
            let hi = hi.wrapping_add(-(C1.to_bits() as i64));
            let lo = lo.wrapping_add(-(C3.to_bits() as i64));
            let lo_carry = lo >> 51;
            let hi = (hi + lo_carry) as u64;
            let lo = lo as u64 & 2_u64.pow(51) - 1;
            let fp = (lo,hi);

            let (lo, hi) = a.widening_mul(b);
            let hi = hi << 13 | lo >> 51;
            let lo = lo & 2_u64.pow(51) - 1;
            let school = (lo, hi);

            prop_assert_eq!(school, fp)
        })
    }
}
