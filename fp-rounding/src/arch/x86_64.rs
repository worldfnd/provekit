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

impl RoundingMode {
    const SHIFT: u32 = 13;
    const BIT_MASK: u32 = 0b11 << SHIFT;

    fn from_bits(bits: u32) -> Self {
        match (bits & Self::BIT_MASK) >> Self::SHIFT {
            0b00 => RoundingMode::Nearest,
            0b01 => RoundingMode::Up,
            0b10 => RoundingMode::Down,
            0b11 => RoundingMode::Zero,
            _ => unreachable!(),
        }
    }

    fn to_bits(self) -> u32 {
        match self {
            RoundingMode::Nearest => 0b00 << Self::SHIFT,
            RoundingMode::Up => 0b01 << Self::SHIFT,
            RoundingMode::Down => 0b10 << Self::SHIFT,
            RoundingMode::Zero => 0b11 << Self::SHIFT,
        }
    }

    unsafe fn read() -> Self {
        let mut mxcsr: u32;
        unsafe {
            asm!(
                "stmxcsr [{ptr}]", // Store MXCSR register value into memory.
                ptr = in(reg) &mut mxcsr,
                options(nostack, preserves_flags)
            );
        }
        Self::from_bits(mxcsr)
    }

    unsafe fn write(self) {
        // Deter compiler/CPU from moving anything around this block
        fence(Ordering::SeqCst);

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

        // Deter compiler/CPU from moving anything around this block
        fence(Ordering::SeqCst);
    }
}
