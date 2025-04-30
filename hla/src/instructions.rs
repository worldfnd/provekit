//! This module provides a collection of assembly instructions as Rust
//! functions.
//!
//! The module includes:
//! - Basic arithmetic operations (add, sub, mul, etc.)
//! - SIMD operations for 2D vectors (fmla2d, shl2d, ushr2d, etc.)
//! - Memory operations (ldr, ldp, stp)
//! - Bitwise operations (and, orr, bic)
//! - Type conversion operations (ucvtf, ucvtf2d)
//! - Flag-based operations (tst, csel, cmn, cinc)
//!
//! Most operations are available in two forms:
//! 1. A high-level function that handles register allocation,
//! 2. A low-level `_inst` function that creates the instruction directly. These
//!    are needed when creating assembly blocks whose instructions can not be
//!    interleaved. See #Safety for more details
//!
//! # How to add instructions
//! For simple instruction use the `embed_asm!` to add the instruction to the
//! DSL. For more complex instructions write the function signature in
//! embed_asm! and use the IDE to inline the macro. This is an easy way to get
//! most of the skeleton needed for more complex operations.
//!
//! # Notes
//!
//! Most instructions are more general than defined here. For now we've only
//! modelled the instructions for our specific use case.
//!
//! # Safety
//! - Flag-based operations should only be used through their `_inst` variants
//!   to prevent interleaving issues that could result in invalid code

use {
    crate::{
        frontend::{Assembler, D, FreshAllocator, PointerReg, Reg, SIMD, Simd, SizedIdx},
        ir::{FreshRegister, Instruction, Modifier},
        reification::ReifyRegister,
    },
    paste::paste,
};
pub use {load_store::*, scalar::*, simd::*};
macro_rules! embed_asm {
    ($name:ident, $opcode:literal, ($($arg:ident : $arg_ty:ty),*) -> $ret_ty:ty) => {
        paste! {
            pub fn $name(alloc: &mut FreshAllocator, asm: &mut Assembler, $($arg: &Reg<$arg_ty>),*) -> Reg<$ret_ty> {
                let ret = alloc.fresh();
                asm.append_instruction(vec![ [<$name _inst>](&ret, $($arg),*) ]);
                ret
            }

            embed_asm_inst!($name, $opcode, ($($arg: $arg_ty),*) -> $ret_ty);
        }
    };
}

macro_rules! embed_asm_inst {
    ($name:ident, $opcode:literal, ($($arg:ident : $arg_ty:ty),*) -> $ret_ty:ty) => {
        paste!{
            pub fn [<$name _inst>](dest: &Reg<$ret_ty>, $($arg: &Reg<$arg_ty>),*) -> Instruction<FreshRegister> {
                Instruction {
                    opcode: $opcode.to_string(),
                    results: vec![dest.reify()],
                    operands: vec![$($arg.reify()),*],
                    modifiers: Modifier::None,
                }
            }
        }
    };
}

pub mod scalar {
    use super::*;
    pub fn mov(alloc: &mut FreshAllocator, asm: &mut Assembler, imm: u64) -> Reg<u64> {
        let ret = alloc.fresh();
        asm.append_instruction(vec![mov_inst(&ret, imm)]);
        ret
    }

    pub fn mov_inst(dest: &Reg<u64>, imm: u64) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "mov".to_string(),
            results:   vec![dest.reify()],
            operands:  vec![],
            modifiers: Modifier::Imm(imm),
        }
    }

    // The following instructions that are only used in assembly blocks
    // as they have side effects such as carries.

    pub fn tst_inst(a: &Reg<u64>, imm: u64) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "tst".to_string(),
            results:   vec![],
            operands:  vec![a.reify()],
            modifiers: Modifier::Imm(imm),
        }
    }

    pub fn csel_inst(
        dest: &Reg<u64>,
        a: &Reg<u64>,
        b: &Reg<u64>,
        cond: &str,
    ) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "csel".to_string(),
            results:   vec![dest.reify()],
            operands:  vec![a.reify(), b.reify()],
            modifiers: Modifier::Cond(cond.to_string()),
        }
    }

    pub fn cmn_inst(a: &Reg<u64>, b: &Reg<u64>) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "cmn".to_string(),
            results:   vec![],
            operands:  vec![a.reify(), b.reify()],
            modifiers: Modifier::None,
        }
    }

    pub fn cinc_inst(dest: &Reg<u64>, a: &Reg<u64>, cond: String) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "cinc".to_string(),
            results:   vec![dest.reify()],
            operands:  vec![a.reify()],
            modifiers: Modifier::Cond(cond),
        }
    }

    embed_asm_inst!(adds, "adds", (a: u64, b: u64) -> u64);
    embed_asm_inst!(adcs, "adcs", (a: u64, b: u64) -> u64);
    embed_asm_inst!(adc, "adc", (a: u64, b: u64) -> u64);
    embed_asm_inst!(subs, "subs", (a: u64, b: u64) -> u64);
    embed_asm_inst!(sbcs, "sbcs", (a: u64, b: u64) -> u64);

    // END block operations

    pub fn movk(alloc: &mut FreshAllocator, asm: &mut Assembler, imm: u16, shift: u8) -> Reg<u64> {
        let ret = alloc.fresh();
        asm.append_instruction(vec![movk_inst(&ret, imm, shift)]);
        ret
    }

    pub fn movk_inst(dest: &Reg<u64>, imm: u16, shift: u8) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "movk".to_string(),
            results:   vec![dest.reify()],
            operands:  vec![],
            modifiers: Modifier::ImmLsl(imm, shift),
        }
    }

    embed_asm!(mul, "mul", (a: u64, b: u64) -> u64);
    embed_asm!(umulh, "umulh", (a: u64, b: u64) -> u64);

    embed_asm!(add, "add", (a: u64, b: u64) -> u64);
    embed_asm!(and, "and", (a: u64, b: u64) -> u64);
}

pub mod load_store {
    use {
        super::*,
        crate::frontend::{MutablePointer, Pointer},
    };
    pub fn ldr<T>(
        alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        ptr: &PointerReg<T>,
    ) -> Reg<u64> {
        let ret = alloc.fresh();
        asm.append_instruction(vec![ldr_inst(&ret, ptr)]);
        ret
    }

    pub fn ldr_inst<T>(dest: &Reg<u64>, ptr: &PointerReg<T>) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "ldr".to_string(),
            results:   vec![dest.reify()],
            operands:  vec![ptr.reify()],
            modifiers: Modifier::None,
        }
    }

    pub fn ldp<PTR: Pointer>(
        alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        ptr: &PTR,
    ) -> (Reg<u64>, Reg<u64>) {
        let ret0 = alloc.fresh();
        let ret1 = alloc.fresh();
        asm.append_instruction(vec![ldp_inst(&ret0, &ret1, ptr)]);
        (ret0, ret1)
    }

    pub fn ldp_inst<PTR: Pointer>(
        dest: &Reg<u64>,
        dest2: &Reg<u64>,
        ptr: &PTR,
    ) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "ldp".to_string(),
            results:   vec![dest.reify(), dest2.reify()],
            operands:  vec![ptr.reify()],
            modifiers: Modifier::None,
        }
    }
    pub fn stp<PTR: MutablePointer>(
        _alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        str0: &Reg<u64>,
        str1: &Reg<u64>,
        ptr: &PTR,
    ) {
        asm.append_instruction(vec![stp_inst(str0, str1, ptr)]);
    }

    pub fn stp_inst<PTR: MutablePointer>(
        dest: &Reg<u64>,
        dest2: &Reg<u64>,
        ptr: &PTR,
    ) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "stp".to_string(),
            results:   vec![],
            operands:  vec![dest.reify(), dest2.reify(), ptr.reify()],
            modifiers: Modifier::None,
        }
    }
}

pub mod simd {
    use {super::*, crate::ir::FreshRegister};

    embed_asm!(ucvtf2d, "ucvtf.2d", (a: Simd<u64,2>) -> Simd<f64,2>);
    embed_asm!(dup2d, "dup.2d", (a: u64) -> Simd<u64,2>);
    embed_asm!(ucvtf, "ucvtf", (a: u64) -> f64);
    embed_asm!(and16, "and.16b", (a: Simd<u64,2>, b: Simd<u64,2>) -> Simd<u64,2>);
    embed_asm!(bic16, "bic.16b", (a: Simd<u64,2>, b: Simd<u64,2>) -> Simd<u64,2>);
    embed_asm!(add2d, "add.2d", (a: Simd<u64,2>, b: Simd<u64,2>) -> Simd<u64,2>);
    embed_asm!(sub2d, "sub.2d", (a: Simd<i64,2>, b: Simd<i64,2>) -> Simd<i64,2>);
    embed_asm!(fsub2d, "fsub.2d", (a: Simd<f64,2>, b: Simd<f64,2>) -> Simd<f64,2>);
    embed_asm!(orr16, "orr.16b", (a: Simd<u64,2>, b: Simd<u64,2>) -> Simd<u64,2>);

    pub fn ins_inst<const I: u8>(
        dest: &SizedIdx<Reg<Simd<u64, 2>>, D, I>,
        a: &Reg<u64>,
    ) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "ins".to_string(),
            results:   vec![dest.reify()],
            operands:  vec![a.reify()],
            modifiers: Modifier::None,
        }
    }

    pub fn umov<const I: u8>(
        alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        a: &SizedIdx<Reg<Simd<u64, 2>>, D, I>,
    ) -> Reg<u64> {
        let ret = alloc.fresh();
        asm.append_instruction(vec![umov_inst(&ret, a)]);
        ret
    }
    pub fn umov_inst<const I: u8>(
        dest: &Reg<u64>,
        a: &SizedIdx<Reg<Simd<u64, 2>>, D, I>,
    ) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "umov".to_string(),
            results:   vec![dest.reify()],
            operands:  vec![a.reify()],
            modifiers: Modifier::None,
        }
    }

    pub fn cmeq2d(
        alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        a: &Reg<Simd<u64, 2>>,
        imm: u64,
    ) -> Reg<Simd<u64, 2>> {
        let ret = alloc.fresh();
        asm.append_instruction(vec![cmeq2d_inst(&ret, a, imm)]);
        ret
    }
    pub fn cmeq2d_inst(
        dest: &Reg<Simd<u64, 2>>,
        a: &Reg<Simd<u64, 2>>,
        imm: u64,
    ) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "cmeq.2d".to_string(),
            results:   vec![dest.reify()],
            operands:  vec![a.reify()],
            modifiers: Modifier::Imm(imm),
        }
    }

    pub fn mov16b<T>(
        alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        a: &Reg<Simd<T, 2>>,
    ) -> Reg<Simd<T, 2>> {
        let ret = alloc.fresh();
        asm.append_instruction(vec![mov16b_inst(&ret, a)]);
        ret
    }
    pub fn mov16b_inst<T>(
        dest: &Reg<Simd<T, 2>>,
        a: &Reg<Simd<T, 2>>,
    ) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "mov.16b".to_string(),
            results:   vec![dest.reify()],
            operands:  vec![a.reify()],
            modifiers: Modifier::None,
        }
    }

    pub fn sli2d(
        _alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        dest: Reg<Simd<u64, 2>>,
        source: &Reg<Simd<u64, 2>>,
        shl: u8,
    ) -> Reg<Simd<u64, 2>> {
        asm.append_instruction(vec![sli2d_inst(&dest, source, shl)]);
        dest
    }
    pub fn sli2d_inst(
        dest: &Reg<Simd<u64, 2>>,
        source: &Reg<Simd<u64, 2>>,
        shl: u8,
    ) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "sli.2d".to_string(),
            results:   vec![dest.reify()],
            operands:  vec![source.reify()],
            modifiers: Modifier::Lsl(shl),
        }
    }

    pub fn fmla2d<T: SIMD + ReifyRegister>(
        _alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        add: Reg<Simd<f64, 2>>,
        a: &Reg<Simd<f64, 2>>,
        b: &T,
    ) -> Reg<Simd<f64, 2>> {
        asm.append_instruction(vec![fmla2d_inst(&add, a, b)]);
        add
    }

    pub fn fmla2d_inst<T: SIMD + ReifyRegister>(
        dest_add: &Reg<Simd<f64, 2>>,
        a: &Reg<Simd<f64, 2>>,
        b: &T,
    ) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "fmla.2d".to_string(),
            results:   vec![dest_add.reify()],
            operands:  vec![a.reify(), b.reify()],
            modifiers: Modifier::None,
        }
    }

    pub fn shl2d(
        alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        a: &Reg<Simd<u64, 2>>,
        imm: u8,
    ) -> Reg<Simd<u64, 2>> {
        let ret = alloc.fresh();
        asm.append_instruction(vec![shl2d_inst(&ret, a, imm)]);
        ret
    }

    pub fn shl2d_inst(
        dest: &Reg<Simd<u64, 2>>,
        a: &Reg<Simd<u64, 2>>,
        imm: u8,
    ) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "shl.2d".to_string(),
            results:   vec![dest.reify()],
            operands:  vec![a.reify()],
            modifiers: Modifier::Lsl(imm),
        }
    }

    pub fn ushr2d(
        alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        a: &Reg<Simd<u64, 2>>,
        imm: u8,
    ) -> Reg<Simd<u64, 2>> {
        let ret = alloc.fresh();
        asm.append_instruction(vec![ushr2d_inst(&ret, a, imm)]);
        ret
    }

    pub fn ushr2d_inst(
        dest: &Reg<Simd<u64, 2>>,
        a: &Reg<Simd<u64, 2>>,
        imm: u8,
    ) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "ushr.2d".to_string(),
            results:   vec![dest.reify()],
            operands:  vec![a.reify()],
            modifiers: Modifier::Lsl(imm),
        }
    }

    pub fn usra2d(
        _alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        add: Reg<Simd<u64, 2>>,
        a: &Reg<Simd<u64, 2>>,
        imm: u8,
    ) -> Reg<Simd<u64, 2>> {
        asm.append_instruction(vec![usra2d_inst(&add, a, imm)]);
        add
    }

    pub fn usra2d_inst(
        dest: &Reg<Simd<u64, 2>>,
        a: &Reg<Simd<u64, 2>>,
        imm: u8,
    ) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "usra.2d".to_string(),
            results:   vec![dest.reify()],
            operands:  vec![a.reify()],
            modifiers: Modifier::Lsl(imm),
        }
    }

    pub fn ssra2d(
        _alloc: &mut FreshAllocator,
        asm: &mut Assembler,
        add: Reg<Simd<i64, 2>>,
        a: &Reg<Simd<i64, 2>>,
        imm: u8,
    ) -> Reg<Simd<i64, 2>> {
        asm.append_instruction(vec![ssra2d_inst(&add, a, imm)]);
        add
    }

    pub fn ssra2d_inst(
        dest: &Reg<Simd<i64, 2>>,
        a: &Reg<Simd<i64, 2>>,
        imm: u8,
    ) -> Instruction<FreshRegister> {
        Instruction {
            opcode:    "ssra.2d".to_string(),
            results:   vec![dest.reify()],
            operands:  vec![a.reify()],
            modifiers: Modifier::Lsl(imm),
        }
    }
}
