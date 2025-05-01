use {
    crate::{constants::*, load_store::load_const},
    hla::*,
    std::array,
};

// BUILDERS

/// Sets up the assembly generation context for a widening multiplication of two
/// u256 numbers.
///
/// Initializes the necessary registers and calls `widening_mul_u256`.
/// Returns the input and output variables for the generated assembly function.
pub fn setup_widening_mul_u256(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
) -> (Vec<FreshVariable>, FreshVariable) {
    let a = alloc.fresh_array();
    let b = alloc.fresh_array();

    let s = widening_mul_u256(alloc, asm, &a, &b);

    (
        vec![FreshVariable::new("a", &a), FreshVariable::new("b", &b)],
        FreshVariable::new("out", &s),
    )
}

/// Sets up the assembly generation context for Montgomery multiplication of two
/// u256 numbers.
///
/// Initializes the necessary registers and calls `montgomery`.
/// Returns the input and output variables for the generated assembly function.
pub fn setup_montgomery(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
) -> (Vec<FreshVariable>, FreshVariable) {
    let a = alloc.fresh_array();
    let b = alloc.fresh_array();

    let s = montgomery(alloc, asm, &a, &b);
    (
        vec![FreshVariable::new("a", &a), FreshVariable::new("b", &b)],
        FreshVariable::new("out", &s),
    )
}

/// Sets up the assembly generation context for a u256 multiply-add-limb
/// operation (`r = r + a * b`).
///
/// Initializes the necessary registers and calls `madd_u256_limb`.
/// Returns the input and output variables for the generated assembly function.
pub fn setup_madd_u256_limb(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
) -> (Vec<FreshVariable>, FreshVariable) {
    let add = alloc.fresh_array();
    let var_add = FreshVariable::new("r#add", &add);
    let a = alloc.fresh_array();
    let b = alloc.fresh();

    let s = madd_u256_limb(alloc, asm, add, &a, &b);

    (
        vec![
            var_add,
            FreshVariable::new("a", &a),
            FreshVariable::new("b", &[b]),
        ],
        FreshVariable::new("out", &s),
    )
}

// GENERATORS

/// Performs `ret = s + [0, add]` with carry propagation.
///
/// Takes a 2-limb value `s` and a single limb `add`.
/// Returns the 2-limb result. Uses `adds` and `cinc` instructions.
pub fn carry_add(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    s: &[Reg<u64>; 2],
    add: &Reg<u64>,
) -> [Reg<u64>; 2] {
    let ret = array::from_fn(|_| alloc.fresh());
    asm.append_instruction(vec![
        adds_inst(&ret[0], &s[0], add),
        cinc_inst(&ret[1], &s[1], "hs".to_string()),
    ]);
    ret
}

/// Performs a compare-negative (`cmn s[0], add`) and propagates the carry to
/// `s[1]`.
///
/// Returns the updated high limb `s[1]`.
pub fn carry_cmn(asm: &mut Assembler, s: [Reg<u64>; 2], add: &Reg<u64>) -> Reg<u64> {
    asm.append_instruction(vec![
        cmn_inst(&s[0], add),
        cinc_inst(&s[1], &s[1], "hs".to_string()),
    ]);
    let [_, out] = s;
    out
}

/// Computes `t += a * b` where `t` is 5 limbs, `a` is 4 limbs, and `b` is 1
/// limb.
///
/// Performs a sequence of widening multiplications and carry additions.
/// Returns the 5-limb result `t`.
pub fn madd_u256_limb(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    mut t: [Reg<u64>; 5],
    a: &[Reg<u64>; 4],
    b: &Reg<u64>,
) -> [Reg<u64>; 5] {
    let mut carry;
    // First multiplication is outside of the loop as it doesn't have the second
    // carry add to add the carry of a previous multiplication
    let tmp = widening_mul(alloc, asm, &a[0], &b);
    [t[0], carry] = carry_add(alloc, asm, &tmp, &t[0]);

    for i in 1..a.len() {
        let tmp = widening_mul(alloc, asm, &a[i], &b);
        let tmp = carry_add(alloc, asm, &tmp, &carry);
        [t[i], carry] = carry_add(alloc, asm, &tmp, &t[i]);
    }
    t[a.len()] = add(alloc, asm, &t[a.len()], &carry);

    t
}

/// Computes `t += a * b` where `t` is 5 limbs, `a` is 4 limbs, and `b` is 1
/// limb, truncating the result to the upper 4 limbs.
///
/// Similar to `madd_u256_limb` but uses `carry_cmn` for the first step and
/// returns only the upper 4 limbs of the result.
///
/// A variation of madd_u256_limb that truncates the results. This is required
/// because the assembler checks whether all registers are used. The HLA
/// performs no optimizations.
pub fn madd_u256_limb_truncate(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    mut t: [Reg<u64>; 5],
    a: &[Reg<u64>; 4],
    b: &Reg<u64>,
) -> [Reg<u64>; 4] {
    let tmp = widening_mul(alloc, asm, &a[0], &b);
    let mut carry = carry_cmn(asm, tmp, &t[0]);
    for i in 1..a.len() {
        let tmp = widening_mul(alloc, asm, &a[i], &b);
        let tmp = carry_add(alloc, asm, &tmp, &carry);
        [t[i], carry] = carry_add(alloc, asm, &tmp, &t[i]);
    }
    t[a.len()] = add(alloc, asm, &t[a.len()], &carry);

    let [_, out @ ..] = t;
    out
}

/// Computes the 8-limb (512-bit) widening multiplication of two 4-limb
/// (256-bit) numbers `a` and `b`.
///
/// Implements the standard schoolbook multiplication algorithm.
pub fn widening_mul_u256(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    a: &[Reg<u64>; 4],
    b: &[Reg<u64>; 4],
) -> [Reg<u64>; 8] {
    let mut t: [Reg<u64>; 8] = array::from_fn(|_| alloc.fresh());
    let mut carry;
    // The all multiplication of a with the lowest limb of b do not have a previous
    // round to add to. That's why this loop is separated.
    [t[0], carry] = widening_mul(alloc, asm, &a[0], &b[0]);
    for i in 1..a.len() {
        let tmp = widening_mul(alloc, asm, &a[i], &b[0]);
        [t[i], carry] = carry_add(alloc, asm, &tmp, &carry);
    }
    t[a.len()] = carry;

    // 2nd and later carry chain
    for j in 1..b.len() {
        let mut carry;
        let tmp = widening_mul(alloc, asm, &a[0], &b[j]);
        [t[j], carry] = carry_add(alloc, asm, &tmp, &t[j]);
        for i in 1..a.len() {
            let tmp = widening_mul(alloc, asm, &a[i], &b[j]);
            let tmp = carry_add(alloc, asm, &tmp, &carry);
            [t[i + j], carry] = carry_add(alloc, asm, &tmp, &t[i + j]);
        }
        t[j + a.len()] = carry;
    }

    t
}

/// Computes `a - b` for two 4-limb (256-bit) numbers with borrow propagation.
///
/// Uses `subs` and `sbcs` instructions.
pub fn sub_u256(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    a: &[Reg<u64>; 4],
    b: &[Reg<u64>; 4],
) -> [Reg<u64>; 4] {
    let out = array::from_fn(|_| alloc.fresh());
    // Due to carry chain this needs to be an atomic block.
    asm.append_instruction(vec![
        subs_inst(&out[0], &a[0], &b[0]),
        sbcs_inst(&out[1], &a[1], &b[1]),
        sbcs_inst(&out[2], &a[2], &b[2]),
        sbcs_inst(&out[3], &a[3], &b[3]),
    ]);
    out
}

/// Reduces a 4-limb number `a` conditionally modulo `2*P`.
///
/// If the most significant bit of `a` is set (i.e., `a >= 2*P`), it subtracts
/// `2*P`. Otherwise, it returns `a`.
///
/// Reduce within 2**256-2p
pub fn reduce(alloc: &mut FreshAllocator, asm: &mut Assembler, a: [Reg<u64>; 4]) -> [Reg<u64>; 4] {
    let p2 = U64_2P.map(|val| load_const(alloc, asm, val));
    let red = sub_u256(alloc, asm, &a, &p2);
    let out = array::from_fn(|_| alloc.fresh());
    asm.append_instruction(vec![
        tst_inst(&a[3], 1 << 63),
        csel_inst(&out[0], &red[0], &a[0], "mi"),
        csel_inst(&out[1], &red[1], &a[1], "mi"),
        csel_inst(&out[2], &red[2], &a[2], "mi"),
        csel_inst(&out[3], &red[3], &a[3], "mi"),
    ]);
    out
}

/// Computes the Montgomery multiplication of two 4-limb (256-bit) numbers `a`
/// and `b`.
///
/// Implements the Domb's single step Montgomery multiplication algorithm.
/// The result is less than `2**256 - P`.
pub fn montgomery(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    a: &[Reg<u64>; 4],
    b: &[Reg<u64>; 4],
) -> [Reg<u64>; 4] {
    let t = widening_mul_u256(alloc, asm, a, b);
    // let [t0, t1, t2, s @ ..] = t;
    let [t0, t1, t2, s @ ..] = t;

    let i3 = U64_I3.map(|val| load_const(alloc, asm, val));
    let r1 = madd_u256_limb(alloc, asm, s, &i3, &t0);

    let i2 = U64_I2.map(|val| load_const(alloc, asm, val));
    let r2 = madd_u256_limb(alloc, asm, r1, &i2, &t1);

    let i1 = U64_I1.map(|val| load_const(alloc, asm, val));
    let r3 = madd_u256_limb(alloc, asm, r2, &i1, &t2);

    let mu0 = load_const(alloc, asm, U64_MU0);
    let m = mul(alloc, asm, &mu0, &r3[0]);

    let p = U64_P.map(|val| load_const(alloc, asm, val));
    let r4 = madd_u256_limb_truncate(alloc, asm, r3, &p, &m);

    reduce(alloc, asm, r4)
}

/// Computes the 128-bit widening multiplication of two 64-bit registers `a` and
/// `b`.
///
/// Returns the low 64 bits (`mul a, b`) and high 64 bits (`umulh a, b`).
pub fn widening_mul(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    a: &Reg<u64>,
    b: &Reg<u64>,
) -> [Reg<u64>; 2] {
    [mul(alloc, asm, a, b), umulh(alloc, asm, a, b)]
}

pub mod experiments {
    use {
        super::*,
        crate::load_store::{load_const, load_u256, store_u256},
    };

    /// Sets up assembly generation for an loading operands for Montgomery
    /// multiplication.
    pub fn setup_single_step_load(
        alloc: &mut FreshAllocator,
        asm: &mut Assembler,
    ) -> (Vec<FreshVariable>, FreshVariable) {
        let mut a = alloc.fresh();
        let b = alloc.fresh();

        single_step_load(alloc, asm, &mut a, &b);

        let var_a = FreshVariable::new("a", &[a]);

        (vec![var_a.clone(), FreshVariable::new("b", &[b])], var_a)
    }

    /// Sets up assembly generation for an experiment using a split Montgomery
    /// multiplication approach.
    pub fn setup_single_step_split(
        alloc: &mut FreshAllocator,
        asm: &mut Assembler,
    ) -> (Vec<FreshVariable>, FreshVariable) {
        let a = alloc.fresh_array();
        let b = alloc.fresh_array();

        let s = single_step_split(alloc, asm, &a, &b);
        (
            vec![FreshVariable::new("a", &a), FreshVariable::new("b", &b)],
            FreshVariable::new("out", &s),
        )
    }

    /// Computes `a * b` where `a` is 4 limbs and `b` is 1 limb, returning a
    /// 5-limb result.
    ///
    /// This is a scalar multiplication used in `single_step_split`.
    pub fn smult(
        alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        a: [Reg<u64>; 4],
        b: Reg<u64>,
    ) -> [Reg<u64>; 5] {
        // Allocates unnecessary fresh registers
        let mut t: [Reg<u64>; 5] = array::from_fn(|_| alloc.fresh());
        // Ouside of the loop because there is no carry add for the left most dword
        [t[0], t[1]] = widening_mul(alloc, asm, &a[0], &b);
        for i in 1..a.len() {
            let lohi = widening_mul(alloc, asm, &a[i], &b);
            [t[i], t[i + 1]] = carry_add(alloc, asm, &lohi, &t[i]);
        }

        t
    }

    /// Computes the 8-limb widening multiplication of two 4-limb numbers loaded
    /// from memory pointers `a` and `b`.
    ///
    /// Similar to `widening_mul_u256` but loads the limbs when needed.
    pub fn school_method_load(
        alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        a: &Reg<*const [u64; 4]>,
        b: &Reg<*const [u64; 4]>,
    ) -> [Reg<u64>; 8] {
        let mut t: [Reg<u64>; 8] = array::from_fn(|_| alloc.fresh());
        let mut carry;
        // The first carry chain is separated out as t doesn't have any values to add
        // first multiplication of a carry chain doesn't not have a carry to add
        let mut a_load: [Reg<u64>; 4] = array::from_fn(|_| alloc.fresh());
        let mut b_load: [Reg<u64>; 4] = array::from_fn(|_| alloc.fresh());

        // TODO loading it one-by-one doesn't have an added benefit as it doesn't
        // reduce the maximum number registers that are used over time.
        // So this could be done with ldp
        a_load[0] = ldr(alloc, asm, &a.get(0));
        b_load[0] = ldr(alloc, asm, &b.get(0));

        [t[0], carry] = widening_mul(alloc, asm, &a_load[0], &b_load[0]);
        for i in 1..a_load.len() {
            a_load[i] = ldr(alloc, asm, &a.get(i));
            let tmp = widening_mul(alloc, asm, &a_load[i], &b_load[0]);
            [t[i], carry] = carry_add(alloc, asm, &tmp, &carry);
        }
        t[a_load.len()] = carry;

        // 2nd and later carry chain
        for j in 1..b_load.len() {
            b_load[j] = ldr(alloc, asm, &b.get(j));
            let mut carry;
            // first multiplication of a carry chain doesn't have a carry to add,
            // but it does have a value already from a previous round
            let tmp = widening_mul(alloc, asm, &a_load[0], &b_load[j]);
            [t[j], carry] = carry_add(alloc, asm, &tmp, &t[j]);
            for i in 1..a_load.len() {
                let tmp = widening_mul(alloc, asm, &a_load[i], &b_load[j]);
                let tmp = carry_add(alloc, asm, &tmp, &carry);
                [t[i + j], carry] = carry_add(alloc, asm, &tmp, &t[i + j]);
            }
            t[j + a_load.len()] = carry;
        }

        t
    }

    /// Performs a single Montgomery multiplication step where operands `a` and
    /// `b` are loaded from memory pointers, and the result is stored back
    /// into the memory pointed to by `a`.
    pub fn single_step_load<'a>(
        alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        a: &Reg<*mut [u64; 4]>,
        b: &Reg<*const [u64; 4]>,
    ) {
        let load_a = load_u256(alloc, asm, a.as_());
        let b = load_u256(alloc, asm, b);

        let res = montgomery(alloc, asm, &load_a, &b);

        store_u256(alloc, asm, &res, a);
    }

    /// Computes `a + b` for two 5-limb numbers with carry propagation.
    ///
    /// Uses `adds`, `adcs`, and `adc` instructions.
    pub fn addv(
        alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        a: [Reg<u64>; 5],
        b: [Reg<u64>; 5],
    ) -> [Reg<u64>; 5] {
        let t: [Reg<u64>; 5] = array::from_fn(|_| alloc.fresh());
        let n: usize = t.len();

        let mut instructions = Vec::new();
        instructions.push(adds_inst(&t[0], &a[0], &b[0]));
        for i in 1..n - 1 {
            instructions.push(adcs_inst(&t[i], &a[i], &b[i]));
        }
        instructions.push(adc_inst(&t[n - 1], &a[n - 1], &b[n - 1]));
        asm.append_instruction(instructions);

        t
    }

    /// Computes `a + b` for two 5-limb numbers, truncating the result to 4
    /// limbs.
    ///
    /// Similar to `addv` but uses `cmn` for the first step and returns only the
    /// upper 4 limbs.
    pub fn addv_truncate(
        alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        a: [Reg<u64>; 5],
        b: [Reg<u64>; 5],
    ) -> [Reg<u64>; 4] {
        let t: [Reg<u64>; 4] = array::from_fn(|_| alloc.fresh());

        let mut instructions = Vec::new();
        instructions.push(cmn_inst(&a[0], &b[0]));
        for i in 1..a.len() {
            instructions.push(adcs_inst(&t[i - 1], &a[i], &b[i]));
        }
        instructions.push(adc_inst(&t[3], &a[4], &b[4]));
        asm.append_instruction(instructions);

        t
    }

    /// Computes the Montgomery multiplication using an alternative split
    /// approach.
    ///
    /// This experimental version uses `smult` and `addv`/`addv_truncate` to
    /// structure the calculation.
    pub fn single_step_split(
        alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        a: &[Reg<u64>; 4],
        b: &[Reg<u64>; 4],
    ) -> [Reg<u64>; 4] {
        let t = widening_mul_u256(alloc, asm, a, b);
        // let [t0, t1, t2, s @ ..] = t;
        let [t0, t1, t2, s @ ..] = t;

        let i3 = U64_I3.map(|val| load_const(alloc, asm, val));
        let r1 = smult(alloc, asm, i3, t0);

        let i2 = U64_I2.map(|val| load_const(alloc, asm, val));
        let r2 = smult(alloc, asm, i2, t1);

        let i1 = U64_I1.map(|val| load_const(alloc, asm, val));
        let r3 = smult(alloc, asm, i1, t2);

        let r4 = addv(alloc, asm, r1, r2);
        let r5 = addv(alloc, asm, r4, r3);
        let r6 = addv(alloc, asm, r5, s);

        let mu0 = load_const(alloc, asm, U64_MU0);
        let m = mul(alloc, asm, &mu0, &r6[0]);

        let p = U64_P.map(|val| load_const(alloc, asm, val));
        let r7 = smult(alloc, asm, p, m);
        let r8 = addv_truncate(alloc, asm, r7, r6);

        reduce(alloc, asm, r8)
    }
}
