// Regression: AND with a non-contiguous literal constant > u32::MAX on a u64
// must compile via the BLACKBOX::AND lowering path.
// Previously rejected by a hardcoded 32-bit cap in `process_binop_opcode`.
fn main(a: u64) -> pub u64 {
    a & 0xF0FFFFFFFF
}
