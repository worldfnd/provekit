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

#[derive(Debug, Clone, Copy, PartialEq)]
enum FPCRState {
    /// FPCR is idle and available for modification
    Idle,
    /// FPCR is actively being used for RTZ operations
    Active,
}

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
    _no_send:  PhantomData<*mut &'id ()>,
}

thread_local! {
    /// Thread-local flag to ensure only one RTZ instance exists per thread.
    /// This prevents multiple concurrent modifications to the FPCR register.
    static FPCR_OWNED: std::cell::Cell<FPCRState> = std::cell::Cell::new(FPCRState::Idle);
}

impl<'id> RTZ<'id> {
    // Why chose FnOnce of FnMut
    // The new_id prevents RTZ from being returned by the closure.
    pub fn new<R>(f: impl for<'new_id> FnOnce(RTZ<'new_id>) -> R) -> R {
        let rtz = RTZ::set();
        f(rtz.unwrap())
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
    fn set() -> Option<RTZ<'id>> {
        // Try to acquire ownership of FPCR
        let state = FPCR_OWNED.with(|owned| {
            let observed_state = owned.get();
            if observed_state == FPCRState::Idle {
                owned.set(FPCRState::Active);
            }
            observed_state
        });

        match state {
            FPCRState::Idle => {
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

                Some(Self {
                    prev_fpcr,
                    _no_send: PhantomData,
                })
            }
            FPCRState::Active => None,
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
    fn write(&self, value: u64) {
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
    /// Restores the original FPCR value and releases the thread-local lock.
    ///
    /// This ensures that the floating-point environment is restored to its
    /// previous state when the RTZ instance is dropped, maintaining the
    /// RAII pattern.
    fn drop(&mut self) {
        // Restore the original FPCR value
        self.write(self.prev_fpcr);
        // Release the thread-local lock
        FPCR_OWNED.with(|owned| owned.set(FPCRState::Idle));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_rtz_single_instance() {
        // First instance should succeed
        let rtz1 = RTZ::set();
        assert!(rtz1.is_some());
        let rtz1 = rtz1.unwrap();
        let beginning_state = rtz1.prev_fpcr;

        // Second instance should fail
        let rtz2 = RTZ::set();
        assert!(rtz2.is_none());

        // Drop first instance
        drop(rtz1);

        // Now we should be able to create a new instance
        let rtz3 = RTZ::set();
        assert!(rtz3.is_some());
        let rtz3 = rtz3.unwrap();

        assert_eq!(beginning_state, rtz3.prev_fpcr);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_rtz_read_write() {
        let rtz = RTZ::set().unwrap();
        let initial = rtz.read();

        // Verify that the rounding mode bits are set
        assert_eq!(initial & FPCR_RMODE_BITS, FPCR_RMODE_BITS);

        // Test write and read back
        let test_value = initial & !FPCR_RMODE_BITS; // Clear rounding mode bits
        rtz.write(test_value);
        assert_eq!(rtz.read(), test_value);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_rtz_new() {
        let out = RTZ::new(|x| {
            let i = RTZ::new(|_y| drop(x));
            5
        });
    }
}
