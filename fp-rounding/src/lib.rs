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
/// serves as a proof that the alternative rounding mode is set.
///
/// # Safety
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

#[inline(always)]
/// Force the evaluation of both the mode and val before an operation
/// that depends on either one of them of them is executed.
fn force_evaluation<T, R>(mode: Mode<'_, T>, val: R) -> (Mode<'_, T>, R) {
    // This is based on the old black_box Criterion before it switched
    // to [`std::hint::black_box`].

    // In tests hint::black_box((mode,val)) works but according to the documentation
    // it must not be relied upon to control critical program behaviour.

    // Another option that was considered was using an empty assembly block
    //     unsafe { asm!("/*{in_var}*/", in_var = in(reg) &dummy as *const T); }
    // Which used to be in libtest albeit using the old LLVM assembly syntax and
    // from what I can tell this is what hint::black_box does under the hood.
    // It is based on [CppCon 2015: Chandler Carruth "Tuning C++: Benchmarks, and CPUs, and Compilers! Oh My!"](https://www.youtube.com/watch?v=nXaxk27zwlk&t=2445s)
    // Caveat in the talk is that this should only be used for benchmarking.

    // Compiler fences have been tried but they do not work. The compiler can see
    // that the mode has independent memory access from val and thus it doesn't
    // prevent reordering.

    // This leaves us with read_volatile which is close to C's volatile behaviour.
    // Downside of this approach is that it adds load and store instructions
    // compared to no extra instructions for black_box/empty assembly block.

    // dummy is needed for tieing the mode and val together. Doing read_volatile on
    // either mode or val alone will not have the desired effect.
    let dummy = (mode, val);
    let copy = unsafe { std::ptr::read_volatile(&raw const dummy) };
    // read_volatile makes a copy, but this is an unintentional side effect.
    // Since running the destructor/Drop twice is undesirable, the memory is
    // freed up here.
    std::mem::forget(dummy);
    copy
}

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
    pub unsafe fn with_rounding_mode<R, A>(
        f: impl for<'new_id> FnOnce(&Mode<'new_id, T>, A) -> R,
        input: A,
    ) -> R {
        // - The branded lifetime new_id + for prevents the Mode token from being leaked
        //   by the closure.
        // - The function f is marked !Send + !Sync due to Mode
        // - The function f takes a reference to [`Mode`] such that on nested calls the
        //   drop order is still correct
        let mode = Mode::new();
        // Tie the mode to the input such that mode will be seated before the first use
        // of input by f.
        // Tieing the input to the Mode does not seem to be strictly necessary, but it's
        // here for added safety.
        let (mode, input) = force_evaluation(mode, input);
        let result = f(&mode, input);
        // Tie the mode to the result such that the computation has to have happened
        // before the old FPCR is restored.
        let (mode, result) = force_evaluation(mode, result);
        unsafe { fpcr::write(mode.prev_fpcr) }
        result
    }

    /// Create a new Mode instance and setting the FPCR accordingly.
    #[inline]
    #[must_use]
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
