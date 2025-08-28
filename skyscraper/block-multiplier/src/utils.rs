use {
    crate::constants::{C1, C2, MASK52, U52_2P, U64_2P},
    std::{
        arch::aarch64::vcvtq_f64_u64,
        array,
        ops::BitAnd,
        simd::{
            cmp::SimdPartialEq,
            num::{SimdFloat, SimdInt, SimdUint},
            Simd, StdFloat,
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

#[inline(always)]
pub fn addv<const N: usize>(mut a: [u64; N], b: [u64; N]) -> [u64; N] {
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
pub const fn make_initial(low_count: usize, high_count: usize) -> u64 {
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
pub fn transpose_simd_to_u256(limbs: [Simd<u64, 2>; 4]) -> [[u64; 4]; 2] {
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
pub fn u260_to_u256_simd(limbs: [Simd<u64, 2>; 5]) -> [Simd<u64, 2>; 4] {
    let [l0, l1, l2, l3, l4] = limbs;
    [
        l0 | (l1 << 52),
        (l1 >> 12) | (l2 << 40),
        (l2 >> 24) | (l3 << 28),
        (l3 >> 36) | (l4 << 16),
    ]
}

#[inline(always)]
pub fn smult_noinit_simd(s: Simd<u64, 2>, v: [u64; 5]) -> [Simd<u64, 2>; 6] {
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
    let twop = U52_2P.map(Simd::splat);
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
        let tmp = a[i] as i128 - b[i] as i128 + borrow;
        c[i] = tmp as u64;
        borrow = tmp >> 64
    }
    c
}

#[inline(always)]
pub fn addv_simd<const N: usize>(
    mut va: [Simd<u64, 2>; N],
    vb: [Simd<u64, 2>; N],
) -> [Simd<u64, 2>; N] {
    for i in 0..va.len() {
        va[i] += vb[i];
    }
    va
}

#[inline(always)]
pub fn carrying_mul_add(a: u64, b: u64, add: u64, carry: u64) -> (u64, u64) {
    let c: u128 = a as u128 * b as u128 + carry as u128 + add as u128;
    (c as u64, (c >> 64) as u64)
}
