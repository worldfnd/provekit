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
    /// Success
    Success            = 0,
    /// Invalid input parameters (null pointers, etc.)
    InvalidInput       = 1,
    /// Failed to read scheme file
    SchemeReadError    = 2,
    /// Failed to read witness/input file
    WitnessReadError   = 3,
    /// Failed to generate proof
    ProofError         = 4,
    /// Failed to serialize output
    SerializationError = 5,
    /// UTF-8 conversion error
    Utf8Error          = 6,
    /// File write error
    FileWriteError     = 7,
}

impl From<PKError> for c_int {
    fn from(error: PKError) -> Self {
        error as c_int
    }
}
