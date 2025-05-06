#![cfg(target_arch = "aarch64")]
//! Floating point rounding mode control for aarch64 architecture.
//!
//! See <https://developer.arm.com/documentation/ddi0595/2021-06/AArch64-Registers/FPCR--Floating-point-Control-Register>
use {crate::RoundingDirection, core::arch::asm};

/// Layout of the floating point control register (FPCR).
const SHIFT: u32 = 22;
const BIT_MASK: u64 = 0b11 << SHIFT;

#[must_use]
fn from_bits(bits: u64) -> RoundingDirection {
    match (bits & BIT_MASK) >> SHIFT {
        0b00 => RoundingDirection::Nearest,
        0b01 => RoundingDirection::Positive,
        0b10 => RoundingDirection::Negative,
        0b11 => RoundingDirection::Zero,
        _ => unreachable!(),
    }
}

#[must_use]
const fn to_bits(mode: RoundingDirection) -> u64 {
    match mode {
        RoundingDirection::Nearest => 0b00 << SHIFT,
        RoundingDirection::Positive => 0b01 << SHIFT,
        RoundingDirection::Negative => 0b10 << SHIFT,
        RoundingDirection::Zero => 0b11 << SHIFT,
    }
}

/// Read the rounding mode bits from the FPCR register
pub unsafe fn read_rounding_mode() -> RoundingDirection {
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
pub unsafe fn write_rounding_mode(mode: RoundingDirection) {
    dbg!(mode);
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
