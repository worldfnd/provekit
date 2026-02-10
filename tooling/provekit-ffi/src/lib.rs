//! FFI bindings for ProveKit, enabling integration with multiple programming
//! languages and platforms.
//!
//! This crate provides C-compatible functions for loading Noir proof schemes,
//! reading witness inputs, and generating proofs that can be called from any
//! language that supports C FFI (Swift, Kotlin, Python, JavaScript, etc.).
//!
//! # Architecture
//!
//! The FFI bindings are organized into several modules:
//! - `types`: Type definitions (PKBuf, PKError, etc.)
//! - `ffi`: Main FFI functions exposed via C ABI
//! - `utils`: Internal utility functions
//!
//! # Usage
//!
//! 1. Call `pk_init()` once before using any other functions
//! 2. Use `pk_prove_to_file()` or `pk_prove_to_json()` to generate proofs
//! 3. Free any returned buffers using `pk_free_buf()`
//!
//! # Safety
//!
//! All FFI functions are marked as `unsafe extern "C"` and require the caller
//! to ensure proper memory management and valid pointer usage.

pub mod ffi;
mod ffi_allocator;
pub mod mmap_allocator;
pub mod types;
pub mod utils;

// Re-export public types and functions for convenience
pub use {ffi::*, types::*};
