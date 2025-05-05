#![allow(unsafe_code)]
//! Round Toward Zero (RTZ) floating-point rounding mode control
//!
//! Rust/LLVM does not support different float point mode rounding modes and
//! this module provides abstractions to able to control the aarch64
//! FPCR (Floating-point Control Register) rounding mode. For how this module
//! provides a safe abstraction see the documentation of [`RTZ`].

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
/// This type provides RAII-style management of the aarch64 FPCR (Floating-point
/// Control Register), specifically for controlling the rounding mode. When
/// created, it sets the rounding mode to "round toward zero" and restores the
/// previous mode when dropped.
///
/// # Safety
///
/// This struct maintains the following invariants:
/// - The previous FPCR value is always restored on drop
/// - The type cannot be sent between threads
///
/// This type is marked !Send + !Sync because FPCR is a per-core / per OS-thread
/// register.
#[derive(Debug)]
pub struct RTZ<'id> {
    prev_fpcr: u64,
    /// Acts as both a marker for !Send + !Sync and as branded type.
    /// In combination with for<'id> in `with_round_mode` this will prevent the
    /// closure from returning the RTZ token.
    _not_send: PhantomData<*mut &'id ()>,
}

impl RTZ<'_> {
    ///  `with_rounding_mode` provides a safe-ish abstraction (see Safety
    /// section) to run a function under round towards zero floating-point
    /// rounding mode. After the closure has been called the rounding mode is
    /// restored to what it was before the call.
    ///
    /// # Safety
    ///
    /// This function is marked unsafe for two reasons:
    ///
    /// 1) Rust/LLVM does not have any built-ins for changing the float point
    ///    mode rounding modes and this won’t prevent the Rust compiler from
    ///    making invalid inferences as described [here](https://github.com/rust-lang/unsafe-code-guidelines/issues/471#issuecomment-1774261953).
    ///
    /// 2) For performance reasons the struct acts as a proof that the rounding
    ///    mode has been set towards round towards zero. It doesn't do any
    ///    subsequent changing of the rounding mode.
    pub unsafe fn with_rounding_mode<R>(f: impl for<'new_id> FnOnce(&RTZ<'new_id>) -> R) -> R {
        // - The branded lifetime new_id + for prevents the RTZ token from being
        //   returned by the closure.
        // - The function f is marked !Send + !Sync due to RTZ
        // - The function f takes a reference to RTZ such that on nested calls the drop
        //   order is still correct
        let rtz = RTZ::new();
        f(&rtz)
        // On drop of rtz the previous FPCR value will be restored
    }

    /// Create a new RTZ instance, setting the FPCR to round-toward-zero mode.
    ///
    /// panics in debug mode when another RTZ instance already exists in this
    /// thread. This is done to detect nesting of the same rounding mode
    #[inline]
    unsafe fn new() -> Self {
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

        // There is no reason to nest calls to with_rounding_mode, but that might
        // incidentally happen so during CI we check for it here.
        debug_assert_ne!(prev_fpcr & FPCR_RMODE_BITS, FPCR_RMODE_BITS);

        Self {
            prev_fpcr,
            _not_send: PhantomData,
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    #[inline]
    fn new() -> Option<RTZ> {
        unimplemented!()
    }

    /// Reads the current value of the FPCR register.
    ///
    /// This method is primarily intended for debugging and verification
    /// purposes.
    #[cfg(target_arch = "aarch64")]
    #[allow(dead_code)]
    #[inline]
    fn read(&self) -> u64 {
        let _ = self;
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
    fn read(&self) -> u64 {
        unimplemented!()
    }

    /// Writes a new value to the FPCR register.
    #[cfg(target_arch = "aarch64")]
    #[inline]
    unsafe fn write(&mut self, value: u64) {
        let _ = self;
        core::arch::asm!(
            "msr fpcr, {}",
            in(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }

    #[cfg(not(target_arch = "aarch64"))]
    #[inline]
    fn write(&self, _value: u64) {
        unimplemented!()
    }
}

impl Drop for RTZ<'_> {
    /// Restores the original FPCR value
    ///
    /// This ensures that the floating-point environment is restored to its
    /// previous state when the RTZ instance is dropped
    fn drop(&mut self) {
        // Restore the original FPCR value
        unsafe {
            self.write(self.prev_fpcr);
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, std::panic};

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_rtz_single_instance() {
        unsafe {
            // First instance should succeed
            let _rtz1 = RTZ::new();

            // Second instance should fail
            let rtz2 = panic::catch_unwind(|| RTZ::new());
            assert!(
                rtz2.is_err(),
                "In debug mode having a nested call to RTZ must fail."
            )
        }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_rtz_read_write() {
        unsafe {
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
}
