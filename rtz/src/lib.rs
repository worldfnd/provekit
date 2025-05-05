#![allow(unsafe_code)]
//! Round Toward Zero (RTZ) floating-point rounding mode control
//!
//! Rust/LLVM does not support different float point mode rounding modes and
//! this module provides abstractions to able to control the AArch64
//! FPCR (Floating-point Control Register) rounding mode. For how this module
//! provides a safe abstraction see the documentation of [`RTZ`].
//!
//! # Safety
//!
//! The FPCR is a per-core register, so this module enforces thread-local usage
//! through the [`RTZ`] type and thread-local state tracking. Multiple instances
//! of [`RTZ`] cannot exist simultaneously in the same thread.

use std::marker::PhantomData;

/// round-toward-zero mode (bits 22-23 to 0b11)
const FPCR_RMODE_BITS: u64 = 0b11 << 22;

/// Proof that Round Toward Zero (RTZ) has been set
///
/// This struct must to be passed as a (unused) reference to any function that
/// requires round toward zero for correct operation. The struct serves as a
/// proof that RTZ is set and we rely on the lifetime introduced
/// by the reference to enforce the ordering of the FPCR operations relative to
/// the multiplication. This way we can prevent the reset of FPCR to bubble up
/// in front of the multiplication.
///
/// This type provides RAII-style management of the AArch64 FPCR (Floating-point
/// Control Register), specifically for controlling the rounding mode. When
/// created, it sets the rounding mode to "round toward zero" and restores the
/// previous mode when dropped.
///
/// # Safety
///
/// This type is not Send because FPCR is a per-core / per OS-thread register.
/// The PhantomData<*mut ()> ensures this. Only one instance can exist per
/// thread at a time, enforced by the FPCR_OWNED thread-local.
#[derive(Debug)]
pub struct RTZ<'id> {
    prev_fpcr: u64,
    // Acts as both not send and as branded type. In combination with for<'id>
    // it will prevent a closure from returning the proof.
    _not_send: PhantomData<*mut &'id ()>,
}

impl<'id> RTZ<'id> {
    // The new_id prevents RTZ from being returned by the closure.
    // f is not send because it captures RTZ which is not send
    pub unsafe fn with_rounding_mode<R>(f: impl for<'new_id> FnOnce(RTZ<'new_id>) -> R) -> R {
        let rtz = RTZ::new();
        f(rtz)
    }
    /// Attempts to create a new RTZ instance, setting the FPCR to
    /// round-toward-zero mode.
    ///
    /// Returns None if another RTZ instance already exists in this thread.
    ///
    /// # Safety
    ///
    /// This function uses inline assembly to modify the FPCR register. The
    /// operations are safe when used as intended through this API, as it
    /// maintains the following invariants:
    /// - Only one instance can exist per thread
    /// - The previous FPCR value is always restored on drop
    /// - The type cannot be sent between threads
    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn new() -> RTZ<'id> {
        let mut prev_fpcr: u64;
        unsafe {
            // Read current FPCR value and set round-toward-zero mode
            core::arch::asm!(
                // Read current FPCR value
                "mrs {prev_fpcr}, fpcr",
                "orr {tmp}, {prev_fpcr}, {rmode}",
                "msr fpcr, {tmp}",
                prev_fpcr = out(reg) prev_fpcr,
                tmp = out(reg) _,
                rmode = const FPCR_RMODE_BITS,
            );
        }

        // Since the call to new is expensive we want to check during CI if no nested
        // calls are happening.
        debug_assert_ne!(prev_fpcr & FPCR_RMODE_BITS, FPCR_RMODE_BITS);

        Self {
            prev_fpcr,
            _not_send: PhantomData,
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    #[inline]
    fn set() -> Option<RTZ> {
        unimplemented!()
    }

    /// Reads the current value of the FPCR register.
    ///
    /// This method is primarily intended for debugging and verification
    /// purposes.
    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn read(&self) -> u64 {
        let mut value: u64;
        unsafe {
            core::arch::asm!(
                "mrs {}, fpcr",
                out(reg) value,
                options(nomem, nostack, preserves_flags)
            );
        }
        value
    }

    #[cfg(not(target_arch = "aarch64"))]
    #[inline]
    pub fn read(&self) -> u64 {
        unimplemented!()
    }

    /// Writes a new value to the FPCR register.
    ///
    /// This is a low-level operation that directly modifies the FPCR register.
    /// It should be used with caution as improper values can affect
    /// floating-point behavior.
    ///
    /// # Safety
    ///
    /// This operation is safe because:
    /// - The RTZ instance proves we have exclusive access to FPCR
    /// - The write operation is atomic
    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn write(&mut self, value: u64) {
        unsafe {
            core::arch::asm!(
                "msr fpcr, {}",
                in(reg) value,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    #[inline]
    pub fn write(&self, _value: u64) {
        todo!()
    }
}

impl<'id> Drop for RTZ<'id> {
    /// Restores the original FPCR value
    ///
    /// This ensures that the floating-point environment is restored to its
    /// previous state when the RTZ instance is dropped
    fn drop(&mut self) {
        // Restore the original FPCR value
        self.write(self.prev_fpcr);
    }
}

#[cfg(test)]
mod tests {
    use {super::*, std::panic};

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_rtz_single_instance() {
        // First instance should succeed
        let _rtz1 = RTZ::new();

        // Second instance should fail
        let rtz2 = panic::catch_unwind(|| RTZ::new());
        assert!(
            rtz2.is_err(),
            "In debug mode having a nested call to RTZ must fail."
        )
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_rtz_read_write() {
        let mut rtz = RTZ::new();
        let initial = rtz.read();

        // Verify that the rounding mode bits are set
        assert_eq!(initial & FPCR_RMODE_BITS, FPCR_RMODE_BITS);

        // Test write and read back
        let test_value = initial & !FPCR_RMODE_BITS; // Clear rounding mode bits
        rtz.write(test_value);
        assert_eq!(rtz.read(), test_value);
    }
}
