#![cfg(target_arch = "aarch64")]
//! Floating point rounding mode control for aarch64 architecture.
//!
//! See <https://developer.arm.com/documentation/ddi0595/2021-06/AArch64-Registers/FPCR--Floating-point-Control-Register>
use {crate::RoundingMode, core::arch::asm};

/// Layout of the floating point control register (FPCR).
const SHIFT: u32 = 21;
const BIT_MASK: u64 = 0b11 << SHIFT;

#[must_use]
fn from_bits(bits: u64) -> RoundingMode {
    match (bits & BIT_MASK) >> SHIFT {
        0b00 => RoundingMode::Nearest,
        0b01 => RoundingMode::Up,
        0b10 => RoundingMode::Down,
        0b11 => RoundingMode::Zero,
        _ => unreachable!(),
    }
}

#[must_use]
const fn to_bits(mode: RoundingMode) -> u64 {
    match mode {
        RoundingMode::Nearest => 0b00 << SHIFT,
        RoundingMode::Up => 0b01 << SHIFT,
        RoundingMode::Down => 0b10 << SHIFT,
        RoundingMode::Zero => 0b11 << SHIFT,
    }
}

/// Read the rounding mode bits from the FPCR register
pub unsafe fn read_rounding_mode() -> RoundingMode {
    let mut bits: u64;
    unsafe {
        asm!(
            "mrs {}, fpcr",
            out(reg) bits,
            options(nomem, nostack, preserves_flags)
        );
    }
    from_bits(bits)
}

/// Update the rounding mode bits in the FPCR register
pub unsafe fn write_rounding_mode(mode: RoundingMode) {
    unsafe {
        asm!(
            "mrs {tmp}, fpcr", // Read Floating Point Control Register into tmp
            "bic {tmp}, {tmp}, {mask}", // Clear the rounding mode bits in tmp
            "orr {tmp}, {tmp}, {bits}", // Set the rounding mode bits in tmp
            "msr fpcr, {tmp}", // Write the modified FPCR value back to the register
            tmp = out(reg) _,
            mask = in(reg) BIT_MASK,
            bits = in(reg) to_bits(mode),
            options(nomem, nostack, preserves_flags)
        );
    }
}
