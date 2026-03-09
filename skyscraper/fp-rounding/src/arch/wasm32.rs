#![cfg(target_arch = "wasm32")]
//! WASM32 stub for floating-point rounding mode control.
//!
//! WebAssembly has well-defined floating-point behavior and doesn't expose
//! rounding mode control. This module provides no-op implementations for WASM32
//! targets.
//!
//! # Correctness note
//!
//! The BN254 multiplier (`bn254-multiplier/src/rne/mono.rs`) uses FMA-based
//! arithmetic that on native targets relies on round-to-zero (RTZ) mode for
//! intermediate results. On WASM32, rounding is always round-to-nearest-even
//! (the IEEE 754 default). The `mono::mul` implementation is designed to
//! tolerate this: its carry-propagation and reduction steps account for
//! nearest-rounding error bounds. Additionally, the WASM build enables
//! `+relaxed-simd` which provides fused multiply-add (FMA) semantics that
//! avoid double-rounding. If you modify the multiplier logic, re-verify
//! correctness under both rounding modes.

use crate::RoundingDirection;

/// Reads the current rounding direction (always Nearest for WASM32)
#[inline]
pub fn read_rounding_mode() -> RoundingDirection {
    RoundingDirection::Nearest
}

/// Sets the rounding direction (no-op for WASM32).
///
/// See module-level docs for correctness implications.
#[inline]
pub fn write_rounding_mode(_mode: RoundingDirection) {
    // No-op: WASM always uses round-to-nearest-even.
}
