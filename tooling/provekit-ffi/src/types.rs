//! Type definitions for ProveKit FFI bindings.

use {
    provekit_common::{Prover, Verifier},
    std::{os::raw::c_int, ptr},
};

/// Buffer structure for returning data to foreign languages.
/// The caller is responsible for freeing the buffer using `pk_free_buf`.
#[repr(C)]
#[must_use = "this buffer must be freed with pk_free_buf"]
pub struct PKBuf {
    /// Pointer to the data
    pub ptr: *mut u8,
    /// Length of the data in bytes
    pub len: usize,
    /// Capacity of the allocation (required for proper deallocation)
    pub cap: usize,
}

impl PKBuf {
    /// Create an empty buffer
    pub fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    /// Create a buffer from a `Vec<u8>`, transferring ownership
    pub fn from_vec(mut v: Vec<u8>) -> Self {
        let ptr = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        std::mem::forget(v); // Transfer ownership to caller
        Self { ptr, len, cap }
    }
}

/// Status codes returned by FFI functions.
#[repr(C)]
#[derive(Debug)]
pub enum PKStatus {
    /// Success
    Success            = 0,
    /// Invalid input parameters (null pointers, etc.)
    InvalidInput       = 1,
    /// Failed to read scheme file
    SchemeReadError    = 2,
    /// Failed to read witness/input file
    WitnessReadError   = 3,
    /// Failed to generate or verify proof
    ProofError         = 4,
    /// Failed to serialize output
    SerializationError = 5,
    /// UTF-8 conversion error
    Utf8Error          = 6,
    /// File write error
    FileWriteError     = 7,
    /// Circuit compilation error
    CompilationError   = 8,
}

impl std::fmt::Display for PKStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Success => "success",
            Self::InvalidInput => "invalid input parameter",
            Self::SchemeReadError => "failed to read proof scheme",
            Self::WitnessReadError => "failed to read witness/input",
            Self::ProofError => "proof generation or verification failed",
            Self::SerializationError => "serialization failed",
            Self::Utf8Error => "invalid UTF-8 in C string",
            Self::FileWriteError => "file write failed",
            Self::CompilationError => "circuit compilation failed",
        })
    }
}

impl std::error::Error for PKStatus {}

impl From<PKStatus> for c_int {
    fn from(status: PKStatus) -> Self {
        status as c_int
    }
}

/// Opaque handle to a compiled prover scheme.
///
/// Holds a `Prover` that is cloned for each prove call (since `Prove::prove`
/// consumes `self`). Thread-safe: `Prover` is `Send + Sync`, and all access
/// through the handle is read-only (clone then use).
///
/// Created by `pk_prepare` or `pk_load_prover`. Must be freed exactly once
/// via `pk_free_prover`.
pub struct PKProver {
    pub(crate) prover: Prover,
}

/// Opaque handle to a compiled verifier scheme.
///
/// Holds a `Verifier` that is cloned for each verify call (since
/// `Verify::verify` consumes `whir_for_witness` via `.take()`). Thread-safe
/// for the same reasons as `PKProver`.
///
/// Created by `pk_prepare` or `pk_load_verifier`. Must be freed exactly once
/// via `pk_free_verifier`.
pub struct PKVerifier {
    pub(crate) verifier: Verifier,
}

// Compile-time assertion: PKProver and PKVerifier must be Send + Sync.
// If a future change adds a non-Send/Sync field, this will fail to compile.
#[allow(dead_code)]
trait AssertSendSync: Send + Sync {}
impl AssertSendSync for PKProver {}
impl AssertSendSync for PKVerifier {}
