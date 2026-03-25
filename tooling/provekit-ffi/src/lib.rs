//! FFI bindings for ProveKit, enabling integration with multiple programming
//! languages and platforms.
//!
//! This crate provides C-compatible functions for compiling Noir circuits,
//! generating proofs, and verifying proofs. It can be called from any
//! language that supports C FFI (Swift, Kotlin, Python, JavaScript, etc.).
//!
//! # Architecture
//!
//! The FFI uses opaque handles (`PKProver`, `PKVerifier`) instead of file
//! paths. The SDK creates handles via `pk_prepare` or `pk_load_*`, uses them
//! for proving/verifying, and frees them when done.
//!
//! # Usage
//!
//! 1. Call `pk_init()` once before using any other functions
//! 2. Call `pk_prepare()` to compile a circuit into prover + verifier handles
//! 3. Call `pk_prove_toml()` or `pk_prove_json()` to generate proofs
//! 4. Call `pk_verify()` to verify proofs
//! 5. Free handles with `pk_free_prover()` / `pk_free_verifier()`
//! 6. Free buffers with `pk_free_buf()`
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
