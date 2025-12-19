#![cfg(target_arch = "wasm32")]
//! WASM32 stub for floating-point rounding mode control.
//!
//! WebAssembly has well-defined floating-point behavior and doesn't expose
//! rounding mode control. This module provides no-op implementations for WASM32
//! targets.

use crate::RoundingDirection;

/// Reads the current rounding direction (always Nearest for WASM32)
#[inline]
pub fn read_rounding_mode() -> RoundingDirection {
    RoundingDirection::Nearest
}

/// Sets the rounding direction (no-op for WASM32)
#[inline]
pub fn write_rounding_mode(_mode: RoundingDirection) {
    // No-op: WASM doesn't allow changing rounding modes
}
