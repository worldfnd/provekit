#![allow(unsafe_code)]
//! Round Toward Zero (RTZ) floating-point rounding mode control
//!
//! Rust/LLVM does not support different float point mode rounding modes and
//! this module provides abstractions to able to control the aarch64
//! FPCR (Floating-point Control Register) rounding mode. For how this module
//! provides a safe abstraction see the documentation of [`Mode`].

mod arch;
mod rounding_direction;
mod rounding_guard;
mod utils;

use crate::utils::fence;
pub use crate::{
    rounding_direction::{
        Nearest, Negative, Positive, RoundingDirection, RoundingDirectionMarker, Zero,
    },
    rounding_guard::RoundingGuard,
};

/// Call closure with a specific rounding mode.
///
///  `with_rounding_mode` provides a safe-ish abstraction (see Safety
/// section) to run a function under a non-default floating-point
/// rounding mode. Once the closure finishes the rounding mode is
/// restored to what it was before the call.
///
/// # Example
///
/// ```rust
/// use fp_rounding::{with_rounding_mode, Positive, RoundingGuard};
///
/// fn requires_round_to_positive(_: &RoundingGuard<Positive>, a: f64) {
///     let b = 2.0_f64.powi(-53);
///     assert_ne!(a + b, a);
///     assert_eq!(a - b, a);
/// }
///
/// unsafe {
///     with_rounding_mode(1.1, requires_round_to_positive);
/// }
/// ```
///
/// # Safety
///
/// This function is marked unsafe for the following reasons:
///
/// 1) Rust/LLVM does not have any built-ins for changing the float point
///    mode rounding modes and this won’t prevent the Rust compiler from
///    making invalid inferences as described [here](https://github.com/rust-lang/unsafe-code-guidelines/issues/471#issuecomment-1774261953).
///
/// 2) For performance reasons the struct acts as a proof that the rounding mode
///    has been set. This means that when you nest two call to
///    `with_rounding_mode` with different rounding modes the closest
///    `with_rounding_mode` in the call stack determines the rounding mode.
pub unsafe fn with_rounding_mode<Mode: RoundingDirectionMarker, Input, Result>(
    input: Input,
    f: impl for<'a> FnOnce(&'a RoundingGuard<Mode>, Input) -> Result,
) -> Result {
    let input = fence(input);
    // - The for 'a prevents the Mode token from being leaked by the closure.
    // - The function f is marked !Send + !Sync due to Mode
    // - The function f takes a reference to [`Mode`] such that on nested calls the
    //   drop order is still correct
    let guard = RoundingGuard::new();
    // Tie the mode to the input such that mode will be seated before the first use
    // of input by f.
    // Tieing the input to the Mode does not seem to be strictly necessary, but it's
    // here for added safety.
    let (guard, input) = fence((guard, input));
    let result = f(&guard, input);
    // Tie the mode to the result such that the computation has to have happened
    // before the old FPCR is restored.
    let (guard, result) = fence((guard, result));
    drop(guard);
    fence(result)
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
fn test_rounding_mode(mode: RoundingDirection) {
    let a = 1.1;
    let b = 2.0_f64.powi(-53);
    let (a, b) = fence((a, b));
    match mode {
        RoundingDirection::Nearest => {
            assert_eq!(a + b, a);
            assert_eq!(a - b, a);
        }
        RoundingDirection::Positive => {
            assert_ne!(a + b, a);
            assert_eq!(a - b, a);
        }
        RoundingDirection::Negative => {
            assert_eq!(a + b, a);
            assert_ne!(a - b, a);
        }
        RoundingDirection::Zero => {
            assert_eq!(a + b, a);
            assert_ne!(a - b, a);
            // TODO: Distinguish from Negative
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn requires_round_to_positive(_: &RoundingGuard<Positive>, _: ()) {
        test_rounding_mode(RoundingDirection::Positive);
    }

    fn requires_round_to_negative(_: &RoundingGuard<Negative>, _: ()) {
        test_rounding_mode(RoundingDirection::Negative);
    }

    fn requires_round_to_nearest(_: &RoundingGuard<Nearest>, _: ()) {
        test_rounding_mode(RoundingDirection::Nearest);
    }

    fn requires_round_to_zero(_: &RoundingGuard<Zero>, _: ()) {
        test_rounding_mode(RoundingDirection::Zero);
    }

    #[test]
    fn test() {
        unsafe {
            with_rounding_mode((), requires_round_to_nearest);
            with_rounding_mode((), requires_round_to_positive);
            with_rounding_mode((), requires_round_to_negative);
            with_rounding_mode((), requires_round_to_zero);
        }
    }
}
