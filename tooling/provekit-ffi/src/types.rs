//! Type definitions for ProveKit FFI bindings.

use std::{os::raw::c_int, ptr};

/// Buffer structure for returning data to foreign languages.
/// The caller is responsible for freeing the buffer using `pk_free_buf`.
#[repr(C)]
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

/// Error codes returned by FFI functions
#[repr(C)]
#[derive(Debug)]
pub enum PKError {
    Success              = 0,
    InvalidInput         = 1,
    SchemeReadError      = 2,
    WitnessReadError     = 3,
    ProofError           = 4,
    SerializationError   = 5,
    Utf8Error            = 6,
    FileWriteError       = 7,
    VerificationFailed   = 8,
    VerifierConsumed     = 9,
    DeserializationError = 10,
}

impl From<PKError> for c_int {
    fn from(error: PKError) -> Self {
        error as c_int
    }
}
