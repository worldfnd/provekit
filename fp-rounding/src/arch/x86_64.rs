#![cfg(target_arch = "x86_64")]
#![allow(unsafe_code)]
//! Floating point rounding mode control for x86_64 architecture.
//!
//! See <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html> Volume 1, Chapter 10.
use {
    crate::RoundingMode,
    core::{
        arch::asm,
        sync::atomic::{fence, Ordering},
    },
};

const SHIFT: u32 = 13;
const BIT_MASK: u32 = 0b11 << SHIFT;

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

pub unsafe fn read_rounding_mode() -> RoundingMode {
    let mut mxcsr: u32;
    unsafe {
        asm!(
            "stmxcsr [{ptr}]", // Store MXCSR register value into memory.
            ptr = in(reg) &mut mxcsr,
            options(nostack, preserves_flags)
        );
    }
    from_bits(mxcsr)
}

pub unsafe fn write_rounding_mode(mode: RoundingMode) {
    // Update the rounding mode bits in the FPCR register
    let mut mxcsr: u32;
    unsafe {
        asm!(
            "stmxcsr [{ptr}]", // Store MXCSR register value into memory.
            ptr = in(reg) &mut mxcsr,
            options(nostack, preserves_flags)
        );
    }
    mxcsr = (mxcsr & !Self::BIT_MASK) | self.to_bits();
    unsafe {
        asm!(
            "ldmxcsr [{}]", // Load MXCSR from memory into register.
            ptr = in(reg) &mxcsr,
            options(nostack, preserves_flags)
        );
    }
}
