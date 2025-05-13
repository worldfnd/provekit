#![cfg(target_arch = "x86_64")]
#![allow(unsafe_code)]
//! Floating point rounding mode control for x86_64 architecture.
//!
//! See <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html> Volume 1, Chapter 10.
use {
    crate::RoundingDirection,
    core::{
        arch::asm,
        sync::atomic::{fence, Ordering},
    },
};

const SHIFT: u32 = 13;
const BIT_MASK: u32 = 0b11 << SHIFT;

#[must_use]
fn from_bits(bits: u32) -> RoundingDirection {
    match (bits & BIT_MASK) >> SHIFT {
        0b00 => RoundingDirection::Nearest,
        0b01 => RoundingDirection::Positive,
        0b10 => RoundingDirection::Negative,
        0b11 => RoundingDirection::Zero,
        _ => unreachable!(),
    }
}

#[must_use]
const fn to_bits(mode: RoundingDirection) -> u32 {
    match mode {
        RoundingDirection::Nearest => 0b00 << SHIFT,
        RoundingDirection::Positive => 0b01 << SHIFT,
        RoundingDirection::Negative => 0b10 << SHIFT,
        RoundingDirection::Zero => 0b11 << SHIFT,
    }
}

pub fn read_rounding_mode() -> RoundingDirection {
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

pub unsafe fn write_rounding_mode(mode: RoundingDirection) {
    // Update the rounding mode bits in the FPCR register
    let mut mxcsr: u32;
    unsafe {
        asm!(
            "stmxcsr [{ptr}]", // Store MXCSR register value into memory.
            ptr = in(reg) &mut mxcsr,
            options(nostack, preserves_flags)
        );
    }
    mxcsr = (mxcsr & !BIT_MASK) | to_bits(mode);
    unsafe {
        asm!(
            "ldmxcsr [{}]", // Load MXCSR from memory into register.
            ptr = in(reg) &mxcsr,
            options(nostack, preserves_flags)
        );
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::test_rounding_mode};

    #[test]
    fn test_read_write() {
        use RoundingDirection::*;
        assert_eq!(read_rounding_mode(), RoundingDirection::Nearest);
        for mode in [Negative, Positive, Zero, Nearest] {
            unsafe {
                write_rounding_mode(mode);
            }
            assert_eq!(read_rounding_mode(), mode);
            test_rounding_mode(mode);
        }
    }
}
