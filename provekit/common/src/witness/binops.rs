/// The number of bits that ACIR uses for the inputs and output of the binop.
pub const BINOP_BITS: usize = 32;

/// The number of bits that used by us for the inputs and output of the binop.
/// 2x this number of bits is used for the lookup table.
pub const BINOP_ATOMIC_BITS: usize = 8;

/// Each operand is decomposed into this many digits.
pub const NUM_DIGITS: usize = BINOP_BITS / BINOP_ATOMIC_BITS;
