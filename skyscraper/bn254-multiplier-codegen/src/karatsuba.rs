//! The scalar Montgomery multiplication kernel [`MUL`].
//!
//! `MUL` uses Domb's single-step reduction with a Karatsuba product, a
//! balanced fold with constants from [`REDUCTION_TABLE`] and a split final
//! step. It returns a loose residue below `2^256`. Inputs must satisfy the
//! caller bound `a, b <= 2^256 - 2p`.

use {
    crate::{constants::*, schoolbook},
    hla::{builder::Setup, *},
    std::array,
};

// Limb positions in `REDUCTION_TABLE`.
const I3_LIMB: usize = 0;
const I2_LIMB: usize = 4;
const I1_LIMB: usize = 8;
const P_LIMB: usize = 12;
const MU0_LIMB: usize = 16;

/// Reduction constants in the layout `MUL` loads them from.
pub const REDUCTION_TABLE: [u64; 17] = {
    let mut table = [0; 17];
    let mut i = 0;
    while i < 4 {
        table[I3_LIMB + i] = U64_I3[i];
        table[I2_LIMB + i] = U64_I2[i];
        table[I1_LIMB + i] = U64_I1[i];
        table[P_LIMB + i] = U64_P[i];
        i += 1;
    }
    table[MU0_LIMB] = U64_MU0;
    table
};

/// Montgomery multiplication: the Karatsuba widening product, the balanced
/// fold of `t0..t2` and the split final step. Inputs `a`, `b` and `table`
/// (the address of `REDUCTION_TABLE`); loose output
pub const MUL: Setup = |alloc, asm| {
    let a = alloc.fresh_array();
    let b = alloc.fresh_array();
    let table = alloc.fresh();
    let t = widening_karatsuba(alloc, asm, &a, &b);
    let s = fold_balanced(alloc, asm, t, &table);
    let out = finish(alloc, asm, s, &table);
    (
        vec![
            FreshVariable::new("a", &a),
            FreshVariable::new("b", &b),
            FreshVariable::new("table", std::slice::from_ref(&table)),
        ],
        FreshVariable::new("out", &out),
    )
};

/// Widening product with one Karatsuba level on the 128-bit halves
fn widening_karatsuba(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    a: &[Reg<u64>; 4],
    b: &[Reg<u64>; 4],
) -> [Reg<u64>; 8] {
    let zero = mov(alloc, asm, 0);
    let fresh2 =
        |alloc: &mut FreshAllocator| -> [Reg<u64>; 2] { array::from_fn(|_| alloc.fresh()) };

    // Write a = a0 + a1·φ and b = b0 + b1·φ with φ = 2^128. Then
    //   a·b = a0·b0 + (a0·b1 + a1·b0)·φ + a1·b1·φ²
    //       = a0·b0 + ((a0 + a1)·(b0 + b1) − a0·b0 − a1·b1)·φ + a1·b1·φ²,
    // so the two cross products cost one product, (a0 + a1)·(b0 + b1).
    //
    // The sums a0 + a1 and b0 + b1 may carry out of 128 bits. Write them as
    // sa = ca·φ + sa' and sb = cb·φ + sb', with carries ca, cb ∈ {0, 1}:
    //   (a0 + a1)·(b0 + b1) = sa'·sb' + (ca·sb' + cb·sa')·φ + ca·cb·φ².
    // So the middle product is the 128-bit product sa'·sb' plus two carry
    // terms. The carries become all-ones masks, which select sb' and sa'
    // with `and` instead of a multiplication.

    let (sa, mask_a) = (fresh2(alloc), alloc.fresh());
    asm.append_instruction(vec![
        adds_inst(&sa[0], &a[0], &a[2]),
        adcs_inst(&sa[1], &a[1], &a[3]),
        csetm_inst(&mask_a, "hs"),
    ]);
    let (sb, mask_b) = (fresh2(alloc), alloc.fresh());
    asm.append_instruction(vec![
        adds_inst(&sb[0], &b[0], &b[2]),
        adcs_inst(&sb[1], &b[1], &b[3]),
        csetm_inst(&mask_b, "hs"),
    ]);
    let ca_sb: [Reg<u64>; 2] = array::from_fn(|i| and(alloc, asm, &sb[i], &mask_a));
    let cb_sa: [Reg<u64>; 2] = array::from_fn(|i| and(alloc, asm, &sa[i], &mask_b));
    let both = and(alloc, asm, &mask_a, &mask_b);
    let both = lsr(alloc, asm, &both, 63);

    let (cross, cross_top) = (fresh2(alloc), alloc.fresh());
    asm.append_instruction(vec![
        adds_inst(&cross[0], &ca_sb[0], &cb_sa[0]),
        adcs_inst(&cross[1], &ca_sb[1], &cb_sa[1]),
        adc_inst(&cross_top, &both, &zero),
    ]);
    let (a_lo, a_hi) = (a.first_chunk().unwrap(), a.last_chunk().unwrap());
    let (b_lo, b_hi) = (b.first_chunk().unwrap(), b.last_chunk().unwrap());
    let low = widening_mul_u128(alloc, asm, a_lo, b_lo);
    let high = widening_mul_u128(alloc, asm, a_hi, b_hi);
    let [m0, m1, m2, m3] = widening_mul_u128(alloc, asm, &sa, &sb);

    let upper: [Reg<u64>; 3] = array::from_fn(|_| alloc.fresh());
    asm.append_instruction(vec![
        adds_inst(&upper[0], &m2, &cross[0]),
        adcs_inst(&upper[1], &m3, &cross[1]),
        adc_inst(&upper[2], &cross_top, &zero),
    ]);
    let [u2, u3, u4] = upper;
    let middle = [m0, m1, u2, u3, u4];
    let minus_low = sub_five(alloc, asm, &middle, &low, &zero);
    let cross_terms = sub_five(alloc, asm, &minus_low, &high, &zero);

    let [l0, l1, l2, l3] = low;
    let [h0, h1, h2, h3] = high;
    let out: [Reg<u64>; 6] = array::from_fn(|_| alloc.fresh());
    asm.append_instruction(vec![
        adds_inst(&out[0], &l2, &cross_terms[0]),
        adcs_inst(&out[1], &l3, &cross_terms[1]),
        adcs_inst(&out[2], &h0, &cross_terms[2]),
        adcs_inst(&out[3], &h1, &cross_terms[3]),
        adcs_inst(&out[4], &h2, &cross_terms[4]),
        adc_inst(&out[5], &h3, &zero),
    ]);
    let [o2, o3, o4, o5, o6, o7] = out;
    [l0, l1, o2, o3, o4, o5, o6, o7]
}

/// Widening multiplication u128 x u128 -> u256 of two-limb `x`, `y`: two rows,
/// one shifted addition.
fn widening_mul_u128(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    x: &[Reg<u64>; 2],
    y: &[Reg<u64>; 2],
) -> [Reg<u64>; 4] {
    let row = |alloc: &mut FreshAllocator, asm: &mut Assembler, j: usize| {
        let [l0, h0] = schoolbook::widening_mul(alloc, asm, &x[0], &y[j]);
        let [l1, h1] = schoolbook::widening_mul(alloc, asm, &x[1], &y[j]);
        let (middle, top) = (alloc.fresh(), alloc.fresh());
        asm.append_instruction(vec![
            adds_inst(&middle, &l1, &h0),
            cinc_inst(&top, &h1, "hs".to_owned()),
        ]);
        [l0, middle, top]
    };
    let [r0, r1, r2] = row(alloc, asm, 0);
    let [s0, s1, s2] = row(alloc, asm, 1);
    let out: [Reg<u64>; 3] = array::from_fn(|_| alloc.fresh());
    asm.append_instruction(vec![
        adds_inst(&out[0], &r1, &s0),
        adcs_inst(&out[1], &r2, &s1),
        cinc_inst(&out[2], &s2, "hs".to_owned()),
    ]);
    let [o1, o2, o3] = out;
    [r0, o1, o2, o3]
}

/// `x - y` for a five-limb `x` and a four-limb `y`; the caller guarantees
/// `x >= y`.
fn sub_five(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    x: &[Reg<u64>; 5],
    y: &[Reg<u64>; 4],
    zero: &Reg<u64>,
) -> [Reg<u64>; 5] {
    let out: [Reg<u64>; 5] = array::from_fn(|_| alloc.fresh());
    let mut instructions = vec![subs_inst(&out[0], &x[0], &y[0])];
    instructions.extend((1..4).map(|i| sbcs_inst(&out[i], &x[i], &y[i])));
    instructions.push(sbcs_inst(&out[4], &x[4], zero));
    asm.append_instruction(instructions);
    out
}

/// The balanced fold `s = (upper + t0*I3) + (t1*I2 + t2*I1)` of the product
/// `t`, five limbs.
fn fold_balanced(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    t: [Reg<u64>; 8],
    table: &Reg<u64>,
) -> [Reg<u64>; 5] {
    let [t0, t1, t2, upper @ ..] = t;
    let p0 = mul_constant(alloc, asm, &t0, I3_LIMB, table);
    // Merge the first pair early to bound live registers. The second pair
    // remains arithmetically independent of this first addition chain.
    let left = add_five(alloc, asm, upper, p0);
    let p1 = mul_constant(alloc, asm, &t1, I2_LIMB, table);
    let p2 = mul_constant(alloc, asm, &t2, I1_LIMB, table);
    let right = add_five(alloc, asm, p1, p2);
    add_five(alloc, asm, left, right)
}

/// `limb * c` for the four-limb constant of `REDUCTION_TABLE` at `first`: five
/// limbs. The eight limb products first, then one carry chain; the table
/// limbs are loaded in pairs, each pair before its products.
fn mul_constant(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    limb: &Reg<u64>,
    first: usize,
    table: &Reg<u64>,
) -> [Reg<u64>; 5] {
    let (c0, c1) = ldp_address(alloc, asm, table, first * 8);
    let p0 = schoolbook::widening_mul(alloc, asm, limb, &c0);
    let p1 = schoolbook::widening_mul(alloc, asm, limb, &c1);
    let (c2, c3) = ldp_address(alloc, asm, table, (first + 2) * 8);
    let p2 = schoolbook::widening_mul(alloc, asm, limb, &c2);
    let p3 = schoolbook::widening_mul(alloc, asm, limb, &c3);
    add_rows(alloc, asm, [p0, p1, p2, p3])
}

/// Sums the 128-bit products `x * c[i]` into five limbs: the low halves
/// occupy limbs 0..4 and the high halves limbs 1..5. One carry chain, which
/// cannot overflow because the full product is below 2^320.
fn add_rows(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    products: [[Reg<u64>; 2]; 4],
) -> [Reg<u64>; 5] {
    let [[l0, h0], [l1, h1], [l2, h2], [l3, h3]] = products;
    let out: [Reg<u64>; 4] = array::from_fn(|_| alloc.fresh());
    asm.append_instruction(vec![
        adds_inst(&out[0], &l1, &h0),
        adcs_inst(&out[1], &l2, &h1),
        adcs_inst(&out[2], &l3, &h2),
        cinc_inst(&out[3], &h3, "hs".to_owned()),
    ]);
    let [o1, o2, o3, o4] = out;
    [l0, o1, o2, o3, o4]
}

fn add_five(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    a: [Reg<u64>; 5],
    b: [Reg<u64>; 5],
) -> [Reg<u64>; 5] {
    let out = array::from_fn(|_| alloc.fresh());
    asm.append_instruction(vec![
        adds_inst(&out[0], &a[0], &b[0]),
        adcs_inst(&out[1], &a[1], &b[1]),
        adcs_inst(&out[2], &a[2], &b[2]),
        adcs_inst(&out[3], &a[3], &b[3]),
        adc_inst(&out[4], &a[4], &b[4]),
    ]);
    out
}

/// The final step on the fold `s`: `m = mu0 * s0`, then `(s + m*p) / 2^64`
/// without `low(m * p[0])` (see [`cancel_split`]).
fn finish(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    s: [Reg<u64>; 5],
    table: &Reg<u64>,
) -> [Reg<u64>; 4] {
    let mu = ldr_address(alloc, asm, table, MU0_LIMB * 8);
    let m = hla::mul(alloc, asm, &mu, &s[0]);
    let (p0, p1) = ldp_address(alloc, asm, table, P_LIMB * 8);
    let (p2, p3) = ldp_address(alloc, asm, table, (P_LIMB + 2) * 8);
    cancel_split(alloc, asm, s, &[p0, p1, p2, p3], &m)
}

/// Computes `(s + m*p) / 2^64` truncated to four limbs for the Montgomery `m`
/// that cancels the low limb. Then `s[0] + low(m*p[0])` is `0` or `2^64`, so
/// its carry is `s[0] != 0` and `low(m*p[0])` is never computed. The low
/// halves of the remaining products are added to `s` in one carry chain and
/// the high halves in a second one; the chains pipeline instead of rippling
/// limb by limb.
fn cancel_split(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    s: [Reg<u64>; 5],
    p: &[Reg<u64>; 4],
    m: &Reg<u64>,
) -> [Reg<u64>; 4] {
    let high0 = umulh(alloc, asm, m, &p[0]);
    let [low1, high1] = schoolbook::widening_mul(alloc, asm, m, &p[1]);
    let [low2, high2] = schoolbook::widening_mul(alloc, asm, m, &p[2]);
    let [low3, high3] = schoolbook::widening_mul(alloc, asm, m, &p[3]);
    let [s0, s1, s2, s3, s4] = s;
    let low: [Reg<u64>; 4] = array::from_fn(|_| alloc.fresh());
    asm.append_instruction(vec![
        cmp_imm_inst(&s0, 1),
        adcs_inst(&low[0], &s1, &low1),
        adcs_inst(&low[1], &s2, &low2),
        adcs_inst(&low[2], &s3, &low3),
        cinc_inst(&low[3], &s4, "hs".to_string()),
    ]);
    let out = array::from_fn(|_| alloc.fresh());
    asm.append_instruction(vec![
        adds_inst(&out[0], &low[0], &high0),
        adcs_inst(&out[1], &low[1], &high1),
        adcs_inst(&out[2], &low[2], &high2),
        adc_inst(&out[3], &low[3], &high3),
    ]);
    out
}
