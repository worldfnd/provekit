use {
    crate::{
        constants::*,
        load_store::{load_const, load_const_simd, load_floating_simd, load_tuple},
    },
    hla::*,
    std::array,
};

/// Sets up the assembly code generation for converting u256 to u260 with a left
/// shift by 2 using immediate values.
///
/// Returns the input and output variables for the generated assembly function.
pub fn setup_u256_to_u260_shl2_imd(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
) -> (Vec<FreshVariable>, FreshVariable) {
    let limbs = alloc.fresh_array();

    let mask = mov(alloc, asm, MASK52);
    let mask_simd = dup2d(alloc, asm, &mask);

    let var_limb = FreshVariable::new("limbs", &limbs);
    let res = u256_to_u260_shl2(alloc, asm, &mask_simd, limbs);

    (vec![var_limb], FreshVariable::new("out", &res))
}

/// Sets up the assembly code generation for converting u260 back to u256 using
/// SIMD instructions.
///
/// Returns the input and output variables for the generated assembly function.
pub fn setup_u260_to_u256_simd(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
) -> (Vec<FreshVariable>, FreshVariable) {
    let limbs = alloc.fresh_array();

    let var_limb = FreshVariable::new("limbs", &limbs);
    let res = u260_to_u256(alloc, asm, limbs);

    (vec![var_limb], FreshVariable::new("out", &res))
}

/// Sets up the assembly code generation for a widening multiplication of two
/// u256 numbers using SIMD instructions.
///
/// Returns the input and output variables for the generated assembly function.
pub fn setup_widening_mul_u256_simd(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
) -> (Vec<FreshVariable>, FreshVariable) {
    let t = alloc.fresh_array();
    let a = alloc.fresh_array();
    let b = alloc.fresh_array();

    let c1 = mov(alloc, asm, C1.to_bits());
    let c1 = dup2d(alloc, asm, &c1);

    // Alternative is c2 = c1 + 1; This requires a change to add to support
    // immediate
    let c2 = load_const(alloc, asm, C2.to_bits());
    let c2 = dup2d(alloc, asm, &c2);
    let var_t = FreshVariable::new("t", &t);
    let var_a = FreshVariable::new("a", &a);
    let var_b = FreshVariable::new("b", &b);

    let res = widening_mul_u256(alloc, asm, &c1, &c2, t, a, b);

    (vec![var_t, var_a, var_b], FreshVariable::new("out", &res))
}

/// Sets up the assembly code generation for a single Montgomery multiplication
/// step using SIMD instructions.
///
/// Returns the input and output variables for the generated assembly function.
pub fn setup_single_step(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
) -> (Vec<FreshVariable>, FreshVariable) {
    let a = alloc.fresh_array();
    let b = alloc.fresh_array(); // Assuming b starts after a

    let var_a = FreshVariable::new("av", &a);
    let var_b = FreshVariable::new("bv", &b);
    let res = single_step(alloc, asm, a, b);

    (vec![var_a, var_b], FreshVariable::new("outv", &res))
}

pub fn setup_square_single_step(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
) -> (Vec<FreshVariable>, FreshVariable) {
    let a = alloc.fresh_array();

    let var_a = FreshVariable::new("av", &a);
    let res = square_single_step(alloc, asm, a);

    (vec![var_a], FreshVariable::new("outv", &res))
}

/// Sets up the assembly code generation for a constant-time reduction using
/// SIMD instructions.
///
/// Returns the input and output variables for the generated assembly function.
pub fn setup_reduce_ct_simd(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
) -> (Vec<FreshVariable>, FreshVariable) {
    let red = alloc.fresh_array();

    let mask = mov(alloc, asm, MASK52);
    let mask52 = dup2d(alloc, asm, &mask);

    let var_red = FreshVariable::new("red", &red);

    let res = reduce(alloc, asm, red).map(|reg| and16(alloc, asm, &reg, &mask52));

    (vec![var_red], FreshVariable::new("out", &res))
}

/// Converts a u256 represented by SIMD registers to a u260 representation with
/// a left shift by 2. This involves shifting and masking operations to pack the
/// 256 bits into 5 limbs of 52 bits each.
fn u256_to_u260_shl2(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    mask52: &Reg<Simd<u64, 2>>,
    limbs: [Reg<Simd<u64, 2>>; 4],
) -> [Reg<Simd<u64, 2>>; 5] {
    let [l0, l1, l2, l3] = limbs;

    let shifted_l1 = shl2d(alloc, asm, &l1, 14);
    let shifted_l2 = shl2d(alloc, asm, &l2, 26);
    let shifted_l3 = shl2d(alloc, asm, &l3, 38);
    // The input and output interface share the same registers. By moving this
    // operation to somewhere in the beginning we can free up the hardware
    // register tied to l3.
    let last = ushr2d(alloc, asm, &l3, 14);

    let shifted_ol0 = shl2d(alloc, asm, &l0, 2);
    let shifted_ol1 = usra2d(alloc, asm, shifted_l1, &l0, 50);
    let shifted_ol2 = usra2d(alloc, asm, shifted_l2, &l1, 38);
    let shifted_ol3 = usra2d(alloc, asm, shifted_l3, &l2, 26);

    [
        and16(alloc, asm, &shifted_ol0, mask52),
        and16(alloc, asm, &shifted_ol1, mask52),
        and16(alloc, asm, &shifted_ol2, mask52),
        and16(alloc, asm, &shifted_ol3, mask52),
        last,
    ]
}

pub const fn heaviside(x: isize) -> usize {
    (x >= 0) as usize
}

#[inline]
pub const fn make_initial(low_count: usize, high_count: usize) -> u64 {
    let val = high_count * 0x467 + low_count * 0x433;
    -((val as i64 & 0xfff) << 52) as u64
}

/// Generates assembly instructions to load the initial floating Montgomery
/// constants into SIMD registers to counteract the biasses that are added to be
/// able to perform 52bit multiplication in the mantissa of a 64 bit floating
/// point. See Emmart <https://ieeexplore.ieee.org/abstract/document/8464792>
fn make_initials(alloc: &mut FreshAllocator, asm: &mut Assembler) -> [Reg<Simd<u64, 2>>; 10] {
    let mut t: [Reg<Simd<u64, 2>>; 10] = array::from_fn(|_| alloc.fresh());

    for i in 0..5 {
        let lower_val = make_initial(i + 1 + 5 * heaviside(i as isize - 4), i);
        let lower_val = mov(alloc, asm, lower_val);

        t[i] = dup2d(alloc, asm, &lower_val);

        let j = 10 - 1 - i;

        let upper_val = make_initial(i + 5 * (1 - heaviside(j as isize - 9)), i + 1 + 5);
        let upper_val = mov(alloc, asm, upper_val);
        t[j] = dup2d(alloc, asm, &upper_val);
    }

    t
}

/// Performs a widening multiplication of two u256 numbers (represented as 5
/// limbs of u260) using floating-point SIMD instructions.
///
/// The inputs `a` and `b` are expected to be biased for floating-point
/// representation. The result `t` accumulates the product `a * b`.
/// Requires the callee to remove the bias that has been used to shift the
/// multiplication operation into the mantissa
fn widening_mul_u256(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    c1: &Reg<Simd<u64, 2>>,
    c2: &Reg<Simd<u64, 2>>,
    mut t: [Reg<Simd<u64, 2>>; 10],
    a: [Reg<Simd<u64, 2>>; 5],
    b: [Reg<Simd<u64, 2>>; 5],
) -> [Reg<Simd<u64, 2>>; 10] {
    let a = a.map(|ai| ucvtf2d(alloc, asm, &ai));
    let b = b.map(|bi| ucvtf2d(alloc, asm, &bi));
    for i in 0..a.len() {
        for j in 0..b.len() {
            let lc1 = mov16b(alloc, asm, c1);

            let hi = fmla2d(alloc, asm, lc1.into_(), &a[i], &b[j]);
            let tmp = fsub2d(alloc, asm, c2.as_(), &hi);
            let lo = fmla2d(alloc, asm, tmp, &a[i], &b[j]);

            t[i + j + 1] = add2d(alloc, asm, &t[i + j + 1], &hi.into_());
            t[i + j] = add2d(alloc, asm, &t[i + j], &lo.into_());
        }
    }
    t
}

fn square_mul_u256(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    c1: &Reg<Simd<u64, 2>>,
    c2: &Reg<Simd<u64, 2>>,
    mut t: [Reg<Simd<u64, 2>>; 10],
    a: [Reg<Simd<u64, 2>>; 5],
) -> [Reg<Simd<u64, 2>>; 10] {
    let a = a.map(|ai| ucvtf2d(alloc, asm, &ai));
    for i in 0..a.len() {
        for j in i..a.len() {
            let lc1 = mov16b(alloc, asm, c1);

            let hi = fmla2d(alloc, asm, lc1.into_(), &a[i], &a[j]);
            let tmp = fsub2d(alloc, asm, c2.as_(), &hi);
            let lo = fmla2d(alloc, asm, tmp, &a[i], &a[j]);

            let (hi, lo) = if i == j {
                (hi.into_(), lo.into_())
            } else {
                // Doubling through addition has higher throughput than through shifting
                (
                    add2d(alloc, asm, hi.as_(), hi.as_()),
                    add2d(alloc, asm, lo.as_(), lo.as_()),
                )
            };

            t[i + j + 1] = add2d(alloc, asm, &t[i + j + 1], &hi);
            t[i + j] = add2d(alloc, asm, &t[i + j], &lo);
        }
    }
    t
}

/// Performs a multiply-add operation: `t += s * v`, where `t` is an array of 6
/// u260 limbs, `s` is a single u260 limb, and `v` is a constant array of 5 u64
/// values. Uses floating-point SIMD instructions with biasing constants `c1`
/// and `c2`.
///
/// Requires the callee to remove the bias that has been used to shift the
/// multiplication operation into the mantissa
fn madd_u256_limb(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    mut t: [Reg<Simd<u64, 2>>; 6],
    constants: &RegisterConstants,
    s: Reg<Simd<u64, 2>>,
    v: [u64; 5],
) -> [Reg<Simd<u64, 2>>; 6] {
    let s = ucvtf2d(alloc, asm, &s);

    // This ordering is the fastest that I've found. Any change or breaking up into
    // parts seem to inhibit bypassing causing a slow down.
    for i in 0..v.len() {
        // skip ucvtf by loading the constant directly as (simd) floating point
        // No measurable difference in loading the vector v completely outside or per
        // element inside the load
        let vs = load_floating_simd(alloc, asm, v[i] as f64);
        let lc1 = mov16b(alloc, asm, &constants.c1);

        let hi = fmla2d(alloc, asm, lc1.into_(), &s, &vs);
        let tmp = fsub2d(alloc, asm, constants.c2.as_(), &hi);
        let lo = fmla2d(alloc, asm, tmp, &s, &vs);

        t[i + 1] = add2d(alloc, asm, &t[i + 1], hi.as_());
        t[i] = add2d(alloc, asm, &t[i], lo.as_());
    }
    t
}

fn single_step(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    a: [Reg<Simd<u64, 2>>; 4],
    b: [Reg<Simd<u64, 2>>; 4],
) -> [Reg<Simd<u64, 2>>; 4] {
    single_step_base(alloc, asm, |alloc, asm, constants| {
        {
            // The be interoperable with the scalar montgomery multiplication we have to
            // compensate for SIMD's mod 260 instead of 256. This is achieved by
            // shifting both inputs by 2.
            let a = u256_to_u260_shl2(alloc, asm, &constants.mask52, a);
            let b = u256_to_u260_shl2(alloc, asm, &constants.mask52, b);
            let t = make_initials(alloc, asm);
            widening_mul_u256(alloc, asm, &constants.c1, &constants.c2, t, a, b)
        }
    })
}

fn square_single_step(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    a: [Reg<Simd<u64, 2>>; 4],
) -> [Reg<Simd<u64, 2>>; 4] {
    single_step_base(alloc, asm, |alloc, asm, constants| {
        {
            // The be interoperable with the scalar montgomery multiplication we have to
            // compensate for SIMD's mod 260 instead of 256. This is achieved by
            // shifting both inputs by 2.
            let a = u256_to_u260_shl2(alloc, asm, &constants.mask52, a);
            let t = make_initials(alloc, asm);
            square_mul_u256(alloc, asm, &constants.c1, &constants.c2, t, a)
        }
    })
}

struct RegisterConstants {
    mask:   Reg<u64>,
    mask52: Reg<Simd<u64, 2>>,
    c1:     Reg<Simd<u64, 2>>,
    c2:     Reg<Simd<u64, 2>>,
}

/// Performs a full Montgomery multiplication of two pairs of two u256 numbers
/// `a` and `b` using SIMD instructions.
fn single_step_base(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    f: impl FnOnce(&mut FreshAllocator, &mut Assembler, &RegisterConstants) -> [Reg<Simd<u64, 2>>; 10],
) -> [Reg<Simd<u64, 2>>; 4] {
    let mask = mov(alloc, asm, MASK52);
    let mask52 = dup2d(alloc, asm, &mask);

    // Biasing constants are kept in registers and passed to functions that require
    // them.
    let c1 = mov(alloc, asm, C1.to_bits());
    let c1 = dup2d(alloc, asm, &c1);

    // Alternative is c2 = c1 + 1; This requires a change to add to support
    // immediate
    let c2 = load_const(alloc, asm, C2.to_bits());
    let c2 = dup2d(alloc, asm, &c2);

    let constants = RegisterConstants {
        mask,
        mask52,
        c1,
        c2,
    };

    let [t0, t1, t2, t3, t4, t5, t6, t7, t8, t9] = f(alloc, asm, &constants);
    let t1 = usra2d(alloc, asm, t1, &t0, 52);
    let t2 = usra2d(alloc, asm, t2, &t1, 52);
    let t3 = usra2d(alloc, asm, t3, &t2, 52);
    let t4 = usra2d(alloc, asm, t4, &t3, 52);

    let t4_10 = [t4, t5, t6, t7, t8, t9];

    let t0 = and16(alloc, asm, &t0, &constants.mask52);
    let t1 = and16(alloc, asm, &t1, &constants.mask52);
    let t2 = and16(alloc, asm, &t2, &constants.mask52);
    let t3 = and16(alloc, asm, &t3, &constants.mask52);

    // loading rho interleaved with multiplication to prevent to prevent allocation
    // a lot of X-registers
    let r0 = madd_u256_limb(alloc, asm, t4_10, &constants, t0, RHO_4);
    let r1 = madd_u256_limb(alloc, asm, r0, &constants, t1, RHO_3);
    let r2 = madd_u256_limb(alloc, asm, r1, &constants, t2, RHO_2);
    let s = madd_u256_limb(alloc, asm, r2, &constants, t3, RHO_1);

    // Could be replaced with fmul, but the rust compiler generates something close
    // to this
    let u52_np0 = load_const(alloc, asm, U52_NP0);
    let s00 = umov(alloc, asm, s[0]._d0());
    let s01 = umov(alloc, asm, s[0]._d1());
    let m0 = mul(alloc, asm, &s00, &u52_np0);
    let m1 = mul(alloc, asm, &s01, &u52_np0);

    let m0 = and(alloc, asm, &m0, &constants.mask);
    let m1 = and(alloc, asm, &m1, &constants.mask);
    let m = load_tuple(alloc, asm, m0, m1);

    let s = madd_u256_limb(alloc, asm, s, &constants, m, U52_P);

    let rs = reduce(alloc, asm, s);

    u260_to_u256(alloc, asm, rs)
}

/// Converts a u260 number (represented as 5 SIMD limbs) back to a u256
/// representation (4 SIMD limbs).
fn u260_to_u256(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    limbs: [Reg<Simd<u64, 2>>; 5],
) -> [Reg<Simd<u64, 2>>; 4] {
    let [l0, l1, l2, l3, l4] = limbs;

    let shifted_l1 = ushr2d(alloc, asm, &l1, 12);
    let shifted_l2 = ushr2d(alloc, asm, &l2, 24);
    let shifted_l3 = ushr2d(alloc, asm, &l3, 36);

    [
        sli2d(alloc, asm, l0, &l1, 52),
        sli2d(alloc, asm, shifted_l1, &l2, 40),
        sli2d(alloc, asm, shifted_l2, &l3, 28),
        sli2d(alloc, asm, shifted_l3, &l4, 16),
    ]
}

/// Performs a reduction step using subtraction of 2*P (U52_2P) conditionally
/// based on the most significant bit. NOTE: This DOESN'T return clean 52 bit
/// limbs as there is still junk in the upper 12 bits. u260-to-u256 will take
/// care of the junk and this allows for saving 5 vector instructions.
fn reduce(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    red: [Reg<Simd<u64, 2>>; 6],
) -> [Reg<Simd<u64, 2>>; 5] {
    // Set cmp to zero if the msb (4x52 + 47) is set.
    let msb_mask = mov(alloc, asm, 1 << 47);
    let msb_mask = dup2d(alloc, asm, &msb_mask);
    let msb = and16(alloc, asm, &red[5], &msb_mask);
    // The comparison state is stored in a vector register instead of NCVF
    // Therefore these operations can be interleaved without making it atomic
    let cmp = cmeq2d(alloc, asm, &msb, 0);

    let subtrahend: [Reg<Simd<_, 2>>; 5] = U52_2P.map(|i| {
        let p = load_const_simd(alloc, asm, i);
        // p & (~cmp) -> if msb is set return p else return 0
        bic16(alloc, asm, &p, &cmp)
    });

    let mut c = array::from_fn(|_| alloc.fresh());
    let [prev, minuend @ ..] = red;
    let mut prev = prev.as_();

    for i in 0..c.len() {
        let tmp = sub2d(alloc, asm, minuend[i].as_(), subtrahend[i].as_());
        // tmp + (prev >> 52)
        let tmp_plus_borrow = ssra2d(alloc, asm, tmp, prev, 52);
        c[i] = tmp_plus_borrow;
        prev = &c[i];
    }

    c.map(|ci| ci.into_())
}
