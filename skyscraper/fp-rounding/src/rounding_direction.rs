//! Round Toward Zero (RTZ) floating-point rounding mode control
//!
//! Rust/LLVM does not support different float point mode rounding modes and
//! this module provides abstractions to able to control the aarch64
//! FPCR (Floating-point Control Register) rounding mode. For how this module
//! provides a safe abstraction see the documentation of [`RoundingDirection`].

use crate::utils::Sealed;

/// IEEE 754 floating point rounding modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoundingDirection {
    /// Round to nearest, ties to even.
    Nearest,
    /// Round toward positive infinity.
    Positive,
    /// Round toward negative infinity.
    Negative,
    /// Round toward zero.
    Zero,
}

/// The IEEE 754 default rounding mode is "round to nearest, ties to even".
///
/// This is what Rust *requires* for correct operation.
impl Default for RoundingDirection {
    fn default() -> Self {
        Self::Nearest
    }
}

/// Type level version of the [`RoundingDirection`] enum using a sealed trait.
#[allow(private_bounds)] // Intentional, this is how it works.
pub trait RoundingDirectionMarker: Sealed {
    /// The rounding mode represented by this marker.
    const MODE: RoundingDirection;
}

/// Round to nearest, ties to even.
pub struct Nearest;
impl Sealed for Nearest {}
impl RoundingDirectionMarker for Nearest {
    const MODE: RoundingDirection = RoundingDirection::Nearest;
}

/// Round toward positive infinity.
pub struct Positive;
impl Sealed for Positive {}
impl RoundingDirectionMarker for Positive {
    const MODE: RoundingDirection = RoundingDirection::Positive;
}

/// Round toward negative infinity.
pub struct Negative;
impl Sealed for Negative {}
impl RoundingDirectionMarker for Negative {
    const MODE: RoundingDirection = RoundingDirection::Negative;
}

/// Round toward zero.
pub struct Zero;
impl Sealed for Zero {}
impl RoundingDirectionMarker for Zero {
    const MODE: RoundingDirection = RoundingDirection::Zero;
}
