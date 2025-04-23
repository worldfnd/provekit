// Masking constants (sanitycheck only) for AND and XOR opcode lookup tables
pub const U8_BIN_LHS_MASK: u32 = 0b000000000000000011111111;
pub const U8_BIN_RHS_MASK: u32 = 0b000000001111111100000000;
pub const U8_BIN_OUT_MASK: u32 = 0b111111110000000000000000;

pub const LHS_SHIFT_FACTOR: u32 = 0;
pub const RHS_SHIFT_FACTOR: u32 = 1 << 8;
pub const OUTPUT_SHIFT_FACTOR: u32 = 1 << 16;

/// Making it slightly easier to generalize the functions for binary operations.
/// Not using this currently.
#[derive(Clone, Debug, Copy)]
pub enum BinOp {
    AND,
    XOR,
}

/// We assume that the inputs being passed in are `u8`s, but we need to output
/// a `u32` since the final representation is the concatenation
pub fn compute_compact_and_logup_repr(lhs: u8, rhs: u8) -> u32 {
    let table_val = (lhs + rhs * (1 << 8) + (lhs & rhs) * (1 << 16)) as u32;
    // --- Sanitycheck ---
    debug_assert_eq!(
        (table_val & U8_BIN_LHS_MASK) & ((table_val * U8_BIN_RHS_MASK) >> 8),
        (table_val & U8_BIN_OUT_MASK) >> 16
    );
    table_val
}
pub fn compute_compact_xor_logup_repr(lhs: u8, rhs: u8) -> u32 {
    let table_val = (lhs + rhs * (1 << 8) + (lhs ^ rhs) * (1 << 16)) as u32;
    // --- Sanitycheck ---
    debug_assert_eq!(
        (table_val & U8_BIN_LHS_MASK) ^ ((table_val * U8_BIN_RHS_MASK) >> 8),
        (table_val & U8_BIN_OUT_MASK) >> 16
    );
    table_val
}
