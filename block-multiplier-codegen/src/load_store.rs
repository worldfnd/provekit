use hla::*;

pub fn load_floating_simd(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    val: f64,
) -> Reg<Simd<f64, 2>> {
    let c = load_const(alloc, asm, val.to_bits());
    dup2d(alloc, asm, &c).into_()
}

/// Loads a u64 by generating a sequence of movk. It's smart enough to detect
/// whether a movk is zero but it doesn't have the logic yet to detect whether
/// the upper bits would fit in the first mov.
pub fn load_const(alloc: &mut FreshAllocator, asm: &mut Assembler, val: u64) -> Reg<u64> {
    // The first load we do with mov instead of movk because of the optimization
    // that leaves moves out.
    let l0 = val as u16;
    let reg = mov(alloc, asm, l0 as u64);

    for i in 1..4 {
        let vali = (val >> (i * 16)) as u16;
        // If the value for limb i is zero then we do not have to emit an instruction.
        if vali != 0 {
            asm.append_instruction(vec![movk_inst(&reg, vali, i * 16)])
        }
    }
    reg
}

pub fn load_const_simd(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    val: u64,
) -> Reg<Simd<u64, 2>> {
    let val = load_const(alloc, asm, val);
    let mask = dup2d(alloc, asm, &val);
    mask
}

pub fn load_tuple(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    fst: Reg<u64>,
    snd: Reg<u64>,
) -> Reg<Simd<u64, 2>> {
    let fresh: Reg<Simd<u64, 2>> = alloc.fresh();
    asm.append_instruction(vec![
        ins_inst(fresh._d0(), &fst),
        ins_inst(fresh._d1(), &snd),
    ]);
    fresh
}

pub fn load_u256(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    a: &Reg<*const [u64; 4]>,
) -> [Reg<u64>; 4] {
    let (l0, l1) = ldp(alloc, asm, a);
    let (l2, l3) = ldp(alloc, asm, &a.get(2));
    [l0, l1, l2, l3]
}

pub fn store_u256(
    alloc: &mut FreshAllocator,
    asm: &mut Assembler,
    a: &[Reg<u64>; 4],
    str: &Reg<*mut [u64; 4]>,
) {
    let [a0, a1, a2, a3] = a;
    stp(alloc, asm, a0, a1, str);
    stp(alloc, asm, a2, a3, &str.get(2));
}
