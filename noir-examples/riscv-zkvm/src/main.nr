const NUM_REGISTERS: usize = 32;
const MAX_STEPS: usize = 32;
const MAX_PROGRAM_WORDS: usize = 64;
const MEM_WORDS: usize = 64;

const OPCODE_LUI: u32 = 0x37;
const OPCODE_AUIPC: u32 = 0x17;
const OPCODE_JAL: u32 = 0x6F;
const OPCODE_JALR: u32 = 0x67;
const OPCODE_BRANCH: u32 = 0x63;
const OPCODE_LOAD: u32 = 0x03;
const OPCODE_STORE: u32 = 0x23;
const OPCODE_OP_IMM: u32 = 0x13;
const OPCODE_OP: u32 = 0x33;
const OPCODE_MISC_MEM: u32 = 0x0F;
const OPCODE_SYSTEM: u32 = 0x73;

const FUNCT3_BEQ: u32 = 0x0;
const FUNCT3_BNE: u32 = 0x1;
const FUNCT3_BLT: u32 = 0x4;
const FUNCT3_BGE: u32 = 0x5;
const FUNCT3_BLTU: u32 = 0x6;
const FUNCT3_BGEU: u32 = 0x7;

const FUNCT3_LB: u32 = 0x0;
const FUNCT3_LH: u32 = 0x1;
const FUNCT3_LW: u32 = 0x2;
const FUNCT3_LBU: u32 = 0x4;
const FUNCT3_LHU: u32 = 0x5;

const FUNCT3_SB: u32 = 0x0;
const FUNCT3_SH: u32 = 0x1;
const FUNCT3_SW: u32 = 0x2;

const FUNCT3_ADDI: u32 = 0x0;
const FUNCT3_SLTI: u32 = 0x2;
const FUNCT3_SLTIU: u32 = 0x3;
const FUNCT3_XORI: u32 = 0x4;
const FUNCT3_ORI: u32 = 0x6;
const FUNCT3_ANDI: u32 = 0x7;
const FUNCT3_SLLI: u32 = 0x1;
const FUNCT3_SRLI_SRAI: u32 = 0x5;

const FUNCT3_ADD_SUB: u32 = 0x0;
const FUNCT3_SLL: u32 = 0x1;
const FUNCT3_SLT: u32 = 0x2;
const FUNCT3_SLTU: u32 = 0x3;
const FUNCT3_XOR: u32 = 0x4;
const FUNCT3_SRL_SRA: u32 = 0x5;
const FUNCT3_OR: u32 = 0x6;
const FUNCT3_AND: u32 = 0x7;

const FUNCT7_SUB: u32 = 0x20;
const FUNCT7_SRA: u32 = 0x20;
const FUNCT7_SLLI: u32 = 0x00;
const FUNCT7_SRLI: u32 = 0x00;
const FUNCT7_SRAI: u32 = 0x20;

const FUNCT7_M_EXTENSION: u32 = 0x01;
const FUNCT3_MUL: u32 = 0x0;
const FUNCT3_MULH: u32 = 0x1;
const FUNCT3_MULHSU: u32 = 0x2;
const FUNCT3_MULHU: u32 = 0x3;
const FUNCT3_DIV: u32 = 0x4;
const FUNCT3_DIVU: u32 = 0x5;
const FUNCT3_REM: u32 = 0x6;
const FUNCT3_REMU: u32 = 0x7;

const FUNCT3_PRIV_CSR: u32 = 0x0;

struct CpuState {
    regs: [u32; NUM_REGISTERS],
    pc: u32,
}

struct Memory {
    words: [u32; MEM_WORDS],
}

impl CpuState {
    fn new(pc: u32, regs: [u32; NUM_REGISTERS]) -> Self {
        CpuState { regs, pc }
    }

    fn read_reg(&self, index: u32) -> u32 {
        assert(index < NUM_REGISTERS as u32, "register index out of bounds");
        self.regs[index as usize]
    }

    fn write_reg(&mut self, index: u32, value: u32) {
        assert(index < NUM_REGISTERS as u32, "register index out of bounds");
        if index != 0 {
            self.regs[index as usize] = value;
        }
    }

    fn enforce_zero_register(&mut self) {
        self.regs[0] = 0;
    }
}

impl Memory {
    fn new(words: [u32; MEM_WORDS]) -> Self {
        Memory { words }
    }

    fn assert_range(&self, addr: u32, size: u32) {
        let start = addr as u64;
        let end = start + size as u64;
        let limit = MEM_WORDS as u64 * 4u64;
        assert(end <= limit, "memory access out of bounds");
    }

    fn read_word(&self, index: u32) -> u32 {
        assert(index < MEM_WORDS as u32, "memory access out of bounds");
        self.words[index as usize]
    }

    fn write_word(&mut self, index: u32, value: u32) {
        assert(index < MEM_WORDS as u32, "memory access out of bounds");
        self.words[index as usize] = value;
    }

    fn load_byte(&self, addr: u32) -> u32 {
        self.assert_range(addr, 1u32);
        let word_index = addr >> 2;
        let byte_offset = addr & 0x3;
        let word = self.read_word(word_index);
        (word >> (byte_offset * 8u32)) & 0xFFu32
    }

    fn load_halfword(&self, addr: u32) -> u32 {
        self.assert_range(addr, 2u32);
        let lower = self.load_byte(addr);
        let upper = self.load_byte(addr + 1u32);
        lower | (upper << 8u32)
    }

    fn load_word(&self, addr: u32) -> u32 {
        self.assert_range(addr, 4u32);
        let b0 = self.load_byte(addr);
        let b1 = self.load_byte(addr + 1u32);
        let b2 = self.load_byte(addr + 2u32);
        let b3 = self.load_byte(addr + 3u32);
        b0 | (b1 << 8u32) | (b2 << 16u32) | (b3 << 24u32)
    }

    fn store_byte(&mut self, addr: u32, value: u32) {
        self.assert_range(addr, 1u32);
        let word_index = addr >> 2;
        let byte_offset = addr & 0x3;
        let word = self.read_word(word_index);
        let mask = !(0xFFu32 << (byte_offset * 8u32));
        let new_word = (word & mask) | ((value & 0xFFu32) << (byte_offset * 8u32));
        self.write_word(word_index, new_word);
    }

    fn store_halfword(&mut self, addr: u32, value: u32) {
        self.assert_range(addr, 2u32);
        self.store_byte(addr, value & 0xFFu32);
        self.store_byte(addr + 1u32, (value >> 8u32) & 0xFFu32);
    }

    fn store_word(&mut self, addr: u32, value: u32) {
        self.assert_range(addr, 4u32);
        self.store_byte(addr, value & 0xFFu32);
        self.store_byte(addr + 1u32, (value >> 8u32) & 0xFFu32);
        self.store_byte(addr + 2u32, (value >> 16u32) & 0xFFu32);
        self.store_byte(addr + 3u32, (value >> 24u32) & 0xFFu32);
    }
}

fn get_bits(value: u32, shift: u32, width: u32) -> u32 {
    if width == 0 {
        return 0;
    }

    let mask = (1u32 << width) - 1u32;
    (value >> shift) & mask
}

fn sign_extend_u32(value: u32, bits: u32) -> u32 {
    let sign_bit = 1u32 << (bits - 1u32);
    if (value & sign_bit) != 0u32 {
        value | (((!0u32) << bits) & 0xFFFF_FFFFu32)
    } else {
        value
    }
}

fn sign_extend_i32(value: u32, bits: u32) -> i32 {
    let extended = sign_extend_u32(value, bits);
    extended as i32
}

fn wrapping_add_u32(a: u32, b: u32) -> u32 {
    let sum: u64 = a as u64 + b as u64;
    (sum & 0xFFFF_FFFFu64) as u32
}

fn wrapping_sub_u32(a: u32, b: u32) -> u32 {
    let extended: u64 = (1u64 << 32) + a as u64;
    let diff: u64 = extended - b as u64;
    (diff & 0xFFFF_FFFFu64) as u32
}

fn wrapping_shift_left(value: u32, shamt: u32) -> u32 {
    (value << (shamt & 0x1Fu32)) & 0xFFFF_FFFFu32
}

fn logical_shift_right(value: u32, shamt: u32) -> u32 {
    value >> (shamt & 0x1Fu32)
}

fn arithmetic_shift_right(value: u32, shamt: u32) -> u32 {
    let signed = value as i32;
    (signed >> (shamt & 0x1Fu32)) as u32
}

fn less_than_signed(a: u32, b: u32) -> bool {
    (a as i32) < (b as i32)
}

fn less_than_unsigned(a: u32, b: u32) -> bool {
    a < b
}

fn mul_64(a: u32, b: u32) -> u64 {
    (a as u64) * (b as u64)
}

fn mul_signed_64(a: i32, b: i32) -> i64 {
    (a as i64) * (b as i64)
}

fn mul_signed_unsigned_64(a: i32, b: u32) -> i64 {
    (a as i64) * (b as i64)
}

fn execute_branch(state: &mut CpuState, funct3: u32, rs1_val: u32, rs2_val: u32, imm: i32) -> bool {
    let mut taken = false;
    if funct3 == FUNCT3_BEQ {
        taken = rs1_val == rs2_val;
    } else if funct3 == FUNCT3_BNE {
        taken = rs1_val != rs2_val;
    } else if funct3 == FUNCT3_BLT {
        taken = less_than_signed(rs1_val, rs2_val);
    } else if funct3 == FUNCT3_BGE {
        taken = !less_than_signed(rs1_val, rs2_val);
    } else if funct3 == FUNCT3_BLTU {
        taken = less_than_unsigned(rs1_val, rs2_val);
    } else {
        assert(funct3 == FUNCT3_BGEU, "unsupported branch instruction");
        taken = !less_than_unsigned(rs1_val, rs2_val);
    }

    if taken {
        state.pc = wrapping_add_u32(state.pc, imm as u32);
    }

    taken
}

fn execute_op(state: &mut CpuState, funct3: u32, funct7: u32, rs1_val: u32, rs2_val: u32) -> u32 {
    if funct7 == FUNCT7_M_EXTENSION {
        if funct3 == FUNCT3_MUL {
            let product = mul_64(rs1_val, rs2_val);
            return (product & 0xFFFF_FFFFu64) as u32;
        } else if funct3 == FUNCT3_MULH {
            let product = mul_signed_64(rs1_val as i32, rs2_val as i32);
            return ((product >> 32) & 0xFFFF_FFFFi64) as u32;
        } else if funct3 == FUNCT3_MULHSU {
            let product = mul_signed_unsigned_64(rs1_val as i32, rs2_val);
            return ((product >> 32) & 0xFFFF_FFFFi64) as u32;
        } else if funct3 == FUNCT3_MULHU {
            let product = mul_64(rs1_val, rs2_val);
            return ((product >> 32) & 0xFFFF_FFFFu64) as u32;
        } else if funct3 == FUNCT3_DIV {
            if rs2_val == 0u32 {
                return 0xFFFF_FFFFu32;
            }

            let dividend = rs1_val as i32;
            let divisor = rs2_val as i32;
            if dividend == -2147483648i32 && divisor == -1i32 {
                return dividend as u32;
            }

            return (dividend / divisor) as u32;
        } else if funct3 == FUNCT3_DIVU {
            if rs2_val == 0u32 {
                return 0xFFFF_FFFFu32;
            }

            return rs1_val / rs2_val;
        } else if funct3 == FUNCT3_REM {
            if rs2_val == 0u32 {
                return rs1_val;
            }

            let dividend = rs1_val as i32;
            let divisor = rs2_val as i32;
            if dividend == -2147483648i32 && divisor == -1i32 {
                return 0u32;
            }

            return (dividend % divisor) as u32;
        } else {
            assert(funct3 == FUNCT3_REMU, "unsupported M extension instruction");
            if rs2_val == 0u32 {
                return rs1_val;
            }

            return rs1_val % rs2_val;
        }
    }

    if funct3 == FUNCT3_ADD_SUB {
        if funct7 == FUNCT7_SUB {
            wrapping_sub_u32(rs1_val, rs2_val)
        } else {
            wrapping_add_u32(rs1_val, rs2_val)
        }
    } else if funct3 == FUNCT3_SLL {
        wrapping_shift_left(rs1_val, rs2_val & 0x1Fu32)
    } else if funct3 == FUNCT3_SLT {
        if less_than_signed(rs1_val, rs2_val) { 1u32 } else { 0u32 }
    } else if funct3 == FUNCT3_SLTU {
        if less_than_unsigned(rs1_val, rs2_val) { 1u32 } else { 0u32 }
    } else if funct3 == FUNCT3_XOR {
        rs1_val ^ rs2_val
    } else if funct3 == FUNCT3_SRL_SRA {
        if funct7 == FUNCT7_SRA {
            arithmetic_shift_right(rs1_val, rs2_val & 0x1Fu32)
        } else {
            logical_shift_right(rs1_val, rs2_val & 0x1Fu32)
        }
    } else if funct3 == FUNCT3_OR {
        rs1_val | rs2_val
    } else {
        assert(funct3 == FUNCT3_AND, "unsupported OP instruction");
        rs1_val & rs2_val
    }
}

fn execute_op_imm(funct3: u32, funct7: u32, rs1_val: u32, imm: u32) -> u32 {
    let imm_se = sign_extend_u32(imm, 12u32);

    if funct3 == FUNCT3_ADDI {
        wrapping_add_u32(rs1_val, imm_se)
    } else if funct3 == FUNCT3_SLTI {
        if less_than_signed(rs1_val, imm_se) { 1u32 } else { 0u32 }
    } else if funct3 == FUNCT3_SLTIU {
        if less_than_unsigned(rs1_val, imm_se) { 1u32 } else { 0u32 }
    } else if funct3 == FUNCT3_XORI {
        rs1_val ^ imm_se
    } else if funct3 == FUNCT3_ORI {
        rs1_val | imm_se
    } else if funct3 == FUNCT3_ANDI {
        rs1_val & imm_se
    } else if funct3 == FUNCT3_SLLI {
        assert(funct7 == FUNCT7_SLLI, "invalid SLLI encoding");
        wrapping_shift_left(rs1_val, imm & 0x1Fu32)
    } else {
        assert(funct3 == FUNCT3_SRLI_SRAI, "unsupported OP-IMM instruction");
        let shamt = imm & 0x1Fu32;
        if funct7 == FUNCT7_SRAI {
            arithmetic_shift_right(rs1_val, shamt)
        } else {
            assert(funct7 == FUNCT7_SRLI, "invalid SRLI encoding");
            logical_shift_right(rs1_val, shamt)
        }
    }
}

fn assert_registers_equal(lhs: [u32; NUM_REGISTERS], rhs: [u32; NUM_REGISTERS]) {
    for i in 0..NUM_REGISTERS {
        assert(lhs[i] == rhs[i], "register mismatch");
    }
}

fn assert_memory_equal(lhs: [u32; MEM_WORDS], rhs: [u32; MEM_WORDS]) {
    for i in 0..MEM_WORDS {
        assert(lhs[i] == rhs[i], "memory mismatch");
    }
}

fn fetch_instruction(program: [u32; MAX_PROGRAM_WORDS], program_len: u32, base_pc: u32, pc: u32) -> u32 {
    assert(pc >= base_pc, "PC before program start");
    assert((pc & 0x3u32) == 0u32, "unaligned PC");
    let index = (pc - base_pc) >> 2;
    assert(index < MAX_PROGRAM_WORDS as u32, "PC beyond program image");
    assert(index < program_len, "PC beyond program length");
    program[index as usize]
}

fn execute_instruction(
    state: &mut CpuState,
    memory: &mut Memory,
    program_base_pc: u32,
    program_len: u32,
    instruction: u32,
) {
    let opcode = instruction & 0x7Fu32;
    let mut next_pc = wrapping_add_u32(state.pc, 4u32);

    if opcode == OPCODE_LUI {
        let rd = get_bits(instruction, 7u32, 5u32);
        let imm = instruction & 0xFFFF_F000u32;
        state.write_reg(rd, imm);
    } else if opcode == OPCODE_AUIPC {
        let rd = get_bits(instruction, 7u32, 5u32);
        let imm = instruction & 0xFFFF_F000u32;
        let result = wrapping_add_u32(state.pc, imm);
        state.write_reg(rd, result);
    } else if opcode == OPCODE_JAL {
        let rd = get_bits(instruction, 7u32, 5u32);
        let imm20 = get_bits(instruction, 31u32, 1u32);
        let imm10_1 = get_bits(instruction, 21u32, 10u32);
        let imm11 = get_bits(instruction, 20u32, 1u32);
        let imm19_12 = get_bits(instruction, 12u32, 8u32);
        let mut imm = (imm20 << 20u32) | (imm19_12 << 12u32) | (imm11 << 11u32) | (imm10_1 << 1u32);
        imm = sign_extend_u32(imm, 21u32);
        state.write_reg(rd, next_pc);
        next_pc = wrapping_add_u32(state.pc, imm);
    } else if opcode == OPCODE_JALR {
        let rd = get_bits(instruction, 7u32, 5u32);
        let funct3 = get_bits(instruction, 12u32, 3u32);
        assert(funct3 == 0u32, "invalid JALR funct3");
        let rs1 = get_bits(instruction, 15u32, 5u32);
        let imm = sign_extend_u32(get_bits(instruction, 20u32, 12u32), 12u32);
        let target = wrapping_add_u32(state.read_reg(rs1), imm);
        let aligned_target = target & !1u32;
        state.write_reg(rd, next_pc);
        next_pc = aligned_target;
    } else if opcode == OPCODE_BRANCH {
        let funct3 = get_bits(instruction, 12u32, 3u32);
        let rs1 = get_bits(instruction, 15u32, 5u32);
        let rs2 = get_bits(instruction, 20u32, 5u32);
        let imm12 = get_bits(instruction, 31u32, 1u32);
        let imm10_5 = get_bits(instruction, 25u32, 6u32);
        let imm4_1 = get_bits(instruction, 8u32, 4u32);
        let imm11 = get_bits(instruction, 7u32, 1u32);
        let mut imm = (imm12 << 12u32) | (imm11 << 11u32) | (imm10_5 << 5u32) | (imm4_1 << 1u32);
        let signed = sign_extend_i32(imm, 13u32);
        let rs1_val = state.read_reg(rs1);
        let rs2_val = state.read_reg(rs2);
        let branch_taken = execute_branch(state, funct3, rs1_val, rs2_val, signed);
        if branch_taken {
            next_pc = state.pc;
        }
    } else if opcode == OPCODE_LOAD {
        let rd = get_bits(instruction, 7u32, 5u32);
        let funct3 = get_bits(instruction, 12u32, 3u32);
        let rs1 = get_bits(instruction, 15u32, 5u32);
        let imm = sign_extend_u32(get_bits(instruction, 20u32, 12u32), 12u32);
        let addr = wrapping_add_u32(state.read_reg(rs1), imm);

        let value = if funct3 == FUNCT3_LB {
            let byte = memory.load_byte(addr);
            sign_extend_u32(byte, 8u32)
        } else if funct3 == FUNCT3_LH {
            let half = memory.load_halfword(addr);
            sign_extend_u32(half, 16u32)
        } else if funct3 == FUNCT3_LW {
            memory.load_word(addr)
        } else if funct3 == FUNCT3_LBU {
            memory.load_byte(addr)
        } else {
            assert(funct3 == FUNCT3_LHU, "unsupported LOAD instruction");
            memory.load_halfword(addr)
        };

        state.write_reg(rd, value);
    } else if opcode == OPCODE_STORE {
        let funct3 = get_bits(instruction, 12u32, 3u32);
        let rs1 = get_bits(instruction, 15u32, 5u32);
        let rs2 = get_bits(instruction, 20u32, 5u32);
        let imm11_5 = get_bits(instruction, 25u32, 7u32);
        let imm4_0 = get_bits(instruction, 7u32, 5u32);
        let imm = sign_extend_u32((imm11_5 << 5u32) | imm4_0, 12u32);
        let addr = wrapping_add_u32(state.read_reg(rs1), imm);
        let rs2_val = state.read_reg(rs2);

        if funct3 == FUNCT3_SB {
            memory.store_byte(addr, rs2_val);
        } else if funct3 == FUNCT3_SH {
            memory.store_halfword(addr, rs2_val);
        } else {
            assert(funct3 == FUNCT3_SW, "unsupported STORE instruction");
            memory.store_word(addr, rs2_val);
        }
    } else if opcode == OPCODE_OP_IMM {
        let rd = get_bits(instruction, 7u32, 5u32);
        let funct3 = get_bits(instruction, 12u32, 3u32);
        let rs1 = get_bits(instruction, 15u32, 5u32);
        let imm = get_bits(instruction, 20u32, 12u32);
        let funct7 = get_bits(instruction, 25u32, 7u32);
        let result = execute_op_imm(funct3, funct7, state.read_reg(rs1), imm);
        state.write_reg(rd, result);
    } else if opcode == OPCODE_OP {
        let rd = get_bits(instruction, 7u32, 5u32);
        let funct3 = get_bits(instruction, 12u32, 3u32);
        let rs1 = get_bits(instruction, 15u32, 5u32);
        let rs2 = get_bits(instruction, 20u32, 5u32);
        let funct7 = get_bits(instruction, 25u32, 7u32);
        let result = execute_op(state, funct3, funct7, state.read_reg(rs1), state.read_reg(rs2));
        state.write_reg(rd, result);
    } else if opcode == OPCODE_MISC_MEM {
        // FENCE and related instructions are treated as nops in this minimal zkVM.
    } else if opcode == OPCODE_SYSTEM {
        let funct3 = get_bits(instruction, 12u32, 3u32);
        assert(funct3 == FUNCT3_PRIV_CSR, "CSR instructions not supported in this zkVM");
        // ECALL/EBREAK halt behaviour is not modelled; treat as failure.
        assert(false, "ECALL/EBREAK not supported");
    } else {
        assert(false, "unsupported opcode");
    }

    state.pc = next_pc;
    assert(state.pc >= program_base_pc, "PC before program start");
    let offset = state.pc - program_base_pc;
    assert((offset & 0x3u32) == 0u32, "PC misaligned after execution");
    assert(offset <= program_len * 4u32, "PC left program range");
    state.enforce_zero_register();
}

fn execute_program(
    program: [u32; MAX_PROGRAM_WORDS],
    program_len: u32,
    num_steps: u32,
    program_base_pc: u32,
    state: &mut CpuState,
    memory: &mut Memory,
) {
    assert(program_len <= MAX_PROGRAM_WORDS as u32, "program too large");
    assert(num_steps <= MAX_STEPS as u32, "trace exceeds capacity");

    for i in 0..MAX_STEPS {
        if (i as u32) < num_steps {
            let pc = state.pc;
            let instruction = fetch_instruction(program, program_len, program_base_pc, pc);
            execute_instruction(state, memory, program_base_pc, program_len, instruction);
        }
    }
}

fn main(
    pub program: [u32; MAX_PROGRAM_WORDS],
    pub program_len: u32,
    pub num_steps: u32,
    pub program_base_pc: u32,
    pub initial_pc: u32,
    pub initial_regs: [u32; NUM_REGISTERS],
    pub initial_memory: [u32; MEM_WORDS],
    pub expected_final_pc: u32,
    pub expected_final_regs: [u32; NUM_REGISTERS],
    pub expected_final_memory: [u32; MEM_WORDS],
) {
    let mut state = CpuState::new(initial_pc, initial_regs);
    let mut memory = Memory::new(initial_memory);

    assert(initial_pc >= program_base_pc, "initial PC before program start");
    let initial_offset = initial_pc - program_base_pc;
    assert((initial_offset & 0x3u32) == 0u32, "initial PC misaligned");
    assert(initial_offset < program_len * 4u32, "initial PC outside program");

    execute_program(
        program,
        program_len,
        num_steps,
        program_base_pc,
        &mut state,
        &mut memory,
    );

    assert(state.pc == expected_final_pc, "final PC does not match");
    assert_registers_equal(state.regs, expected_final_regs);
    assert_memory_equal(memory.words, expected_final_memory);
}
