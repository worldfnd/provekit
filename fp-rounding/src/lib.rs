#![allow(unsafe_code)]
//! Round Toward Zero (RTZ) floating-point rounding mode control
//!
//! Rust/LLVM does not support different float point mode rounding modes and
//! this module provides abstractions to able to control the aarch64
//! FPCR (Floating-point Control Register) rounding mode. For how this module
//! provides a safe abstraction see the documentation of [`Mode`].

use std::marker::PhantomData;

/// Proof that the floating-point rounding mode has been set
///
/// This struct must to be passed as a (unused) reference to any function that
/// requires the non-default rounding mode for correct operation. The struct
/// serves as a proof that the alternative rounding mode is set and we rely on
/// the lifetime introduced by the reference to enforce the ordering of the FPCR
/// operations relative to the multiplication. This way we can prevent the reset
/// of FPCR to bubble up in front of the multiplication.
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
pub struct Mode<'id, T> {
    prev_fpcr: u64,
    /// Acts as a marker for:
    /// - !Send + !Sync;
    /// - a branded type that in combination with for<'id> in
    ///   `with_rounding_mode` will prevent the closure from leaking the Mode
    ///   token.
    /// - The kind of rounding mode
    _marker:   PhantomData<*mut &'id T>,
}

/// Marker type for the Round Toward Zero (RTZ) rounding mode.
///
/// This type is used as a parameter for [`Mode`] to specify the
/// dependency on RTZ at the type-level.
pub struct RTZ;

impl<T: ModeMask> Mode<'_, T> {
    ///  `with_rounding_mode` provides a safe-ish abstraction (see Safety
    /// section) to run a function under a non-default floating-point
    /// rounding mode. Once the closure finishes the rounding mode is
    /// restored to what it was before the call.
    ///
    /// # Safety
    ///
    /// This function is marked unsafe for the following reasons:
    ///
    /// 1) Rust/LLVM does not have any built-ins for changing the float point
    ///    mode rounding modes and this won’t prevent the Rust compiler from
    ///    making invalid inferences as described [here](https://github.com/rust-lang/unsafe-code-guidelines/issues/471#issuecomment-1774261953).
    ///
    /// 2) For performance reasons the struct acts as a proof that the rounding
    ///    mode has been set. This means that when you nest two call to
    ///    `with_rounding_mode` with different rounding modes the closest
    ///    `with_rounding_mode` in the call stack determines the rounding mode.
    pub unsafe fn with_rounding_mode<R>(f: impl for<'new_id> FnOnce(&Mode<'new_id, T>) -> R) -> R {
        // - The branded lifetime new_id + for prevents the Mode token from being leaked
        //   by the closure.
        // - The function f is marked !Send + !Sync due to Mode
        // - The function f takes a reference to [`Mode`] such that on nested calls the
        //   drop order is still correct
        let mode = Mode::new();
        f(&mode)
        // On drop of mode the previous FPCR value will be restored
    }

    /// Create a new Mode instance and setting the FPCR accordingly.
    #[inline]
    unsafe fn new() -> Self {
        let prev_fpcr = fpcr::set_rounding_mode(T::MASK);
        Self {
            prev_fpcr,
            _marker: PhantomData,
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    #[inline]
    fn new() -> Option<Mode> {
        unimplemented!()
    }
}

/// Trait for defining floating-point rounding mode masks for the rounding mode
/// marker types
///
/// The MASK constant represents the bits that need to be set in the FPCR
/// to enable the specific rounding mode.
pub trait ModeMask {
    /// The bit mask to be applied to the FPCR register
    const MASK: u64;
}

impl ModeMask for RTZ {
    const MASK: u64 = 0b11 << 22;
}

impl<T> Drop for Mode<'_, T> {
    /// Restores the original FPCR value
    ///
    /// This ensures that the floating-point environment is restored to its
    /// previous state.
    fn drop(&mut self) {
        // Restore the original FPCR value
        unsafe {
            fpcr::write(self.prev_fpcr);
        }
    }
}

mod fpcr {

    #[inline]
    pub unsafe fn set_rounding_mode(mode_mask: u64) -> u64 {
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
                rmode = in(reg) mode_mask,
            );
        }

        // There is no reason to nest calls to with_rounding_mode without changing the
        // rounding mode. However do to it's interface that might accidentally
        // so during CI we check for it here.
        debug_assert_ne!(prev_fpcr & mode_mask, mode_mask);
        prev_fpcr
    }

    /// Reads the current value of the FPCR register.
    ///
    /// This method is primarily intended for debugging and verification
    /// purposes.
    #[cfg(target_arch = "aarch64")]
    #[allow(dead_code)]
    #[inline]
    pub fn read() -> u64 {
        let mut value: u64;
        unsafe {
            core::arch::asm!(
                "mrs {}, fpcr",
                out(reg) value,
                options(nostack, preserves_flags)
            );
        }
        value
    }

    #[cfg(not(target_arch = "aarch64"))]
    #[inline]
    fn read() -> u64 {
        unimplemented!()
    }

    /// Writes a new value to the FPCR register.
    #[cfg(target_arch = "aarch64")]
    #[inline]
    pub unsafe fn write(value: u64) {
        core::arch::asm!(
            "msr fpcr, {}",
            in(reg) value,
            options(nostack, preserves_flags)
        );
    }

    #[cfg(not(target_arch = "aarch64"))]
    #[inline]
    fn write(_value: u64) {
        unimplemented!()
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
            let _rtz1: Mode<'_, RTZ> = Mode::new();

            // Second instance should fail
            let rtz2 = panic::catch_unwind(|| Mode::<'_, RTZ>::new());
            assert!(
                rtz2.is_err(),
                "In debug mode having a nested call to RTZ must fail."
            )
        }
    }

    /// round-toward-zero mode (bits 22-23 to 0b11)
    const FPCR_RMODE_BITS: u64 = 0b11 << 22;

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_rtz_read_write() {
        unsafe {
            let _rtz: Mode<'_, RTZ> = Mode::new();
            let initial = fpcr::read();

            // Verify that the rounding mode bits are set
            assert_eq!(initial & FPCR_RMODE_BITS, FPCR_RMODE_BITS);

            // Test write and read back
            let test_value = initial & !FPCR_RMODE_BITS; // Clear rounding mode bits
            fpcr::write(test_value);
            assert_eq!(fpcr::read(), test_value);
        }
    }
}
