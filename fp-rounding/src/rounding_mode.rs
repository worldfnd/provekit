//! Round Toward Zero (RTZ) floating-point rounding mode control
//!
//! Rust/LLVM does not support different float point mode rounding modes and
//! this module provides abstractions to able to control the aarch64
//! FPCR (Floating-point Control Register) rounding mode. For how this module
//! provides a safe abstraction see the documentation of [`Mode`].

use crate::utils::Sealed;

/// IEEE 754 floating point rounding modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoundingMode {
    /// Round to nearest, ties to even.
    Nearest,
    /// Round toward positive infinity.
    Up,
    /// Round toward negative infinity.
    Down,
    /// Round toward zero.
    Zero,
}

/// The IEEE 754 default rounding mode is "round to nearest, ties to even".
///
/// This is what Rust *requires* for correct operation.
impl Default for RoundingMode {
    fn default() -> Self {
        Self::Nearest
    }
}

/// Type level version of the [`RoundingMode`] enum using a sealed trait.
#[allow(private_bounds)] // Intentional, this is how it works.
pub trait RoundingModeMarker: Sealed {
    /// The rounding mode represented by this marker.
    const MODE: RoundingMode;
}

/// Round to nearest, ties to even.
pub struct Nearest;
impl Sealed for Nearest {}
impl RoundingModeMarker for Nearest {
    const MODE: RoundingMode = RoundingMode::Nearest;
}

/// Round toward positive infinity.
pub struct Up;
impl Sealed for Up {}
impl RoundingModeMarker for Up {
    const MODE: RoundingMode = RoundingMode::Up;
}

/// Round toward negative infinity.
pub struct Down;
impl Sealed for Down {}
impl RoundingModeMarker for Down {
    const MODE: RoundingMode = RoundingMode::Down;
}

/// Round toward zero.
pub struct Zero;
impl Sealed for Zero {}
impl RoundingModeMarker for Zero {
    const MODE: RoundingMode = RoundingMode::Zero;
}
