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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PKBuf tests
    // -----------------------------------------------------------------------

    #[test]
    fn pkbuf_empty_has_null_ptr() {
        let buf = PKBuf::empty();
        assert!(buf.ptr.is_null());
        assert_eq!(buf.len, 0);
        assert_eq!(buf.cap, 0);
    }

    #[test]
    fn pkbuf_from_vec_captures_metadata() {
        let data: Vec<u8> = vec![1, 2, 3, 4, 5];
        let expected_ptr = data.as_ptr();
        let expected_len = data.len();
        let expected_cap = data.capacity();
        let buf = PKBuf::from_vec(data);
        // ptr must point to the same allocation
        assert_eq!(buf.ptr as *const u8, expected_ptr);
        assert_eq!(buf.len, expected_len);
        assert_eq!(buf.cap, expected_cap);
        // Reconstruct to avoid leak in test
        unsafe {
            drop(Vec::from_raw_parts(buf.ptr, buf.len, buf.cap));
        }
    }

    #[test]
    fn pkbuf_from_vec_nonempty_has_nonnull_ptr() {
        let buf = PKBuf::from_vec(vec![42u8]);
        assert!(!buf.ptr.is_null());
        assert_eq!(buf.len, 1);
        unsafe {
            drop(Vec::from_raw_parts(buf.ptr, buf.len, buf.cap));
        }
    }

    // -----------------------------------------------------------------------
    // PKStatus → c_int conversion tests
    // -----------------------------------------------------------------------

    #[test]
    fn pkstatus_codes_are_correct() {
        let cases: &[(PKStatus, i32)] = &[
            (PKStatus::Success, 0),
            (PKStatus::InvalidInput, 1),
            (PKStatus::SchemeReadError, 2),
            (PKStatus::WitnessReadError, 3),
            (PKStatus::ProofError, 4),
            (PKStatus::SerializationError, 5),
            (PKStatus::Utf8Error, 6),
            (PKStatus::FileWriteError, 7),
            (PKStatus::CompilationError, 8),
        ];
        for (status, expected) in cases {
            // Use format to avoid consuming the enum value
            let code: c_int = match status {
                PKStatus::Success => PKStatus::Success.into(),
                PKStatus::InvalidInput => PKStatus::InvalidInput.into(),
                PKStatus::SchemeReadError => PKStatus::SchemeReadError.into(),
                PKStatus::WitnessReadError => PKStatus::WitnessReadError.into(),
                PKStatus::ProofError => PKStatus::ProofError.into(),
                PKStatus::SerializationError => PKStatus::SerializationError.into(),
                PKStatus::Utf8Error => PKStatus::Utf8Error.into(),
                PKStatus::FileWriteError => PKStatus::FileWriteError.into(),
                PKStatus::CompilationError => PKStatus::CompilationError.into(),
            };
            assert_eq!(
                code, *expected,
                "PKStatus::{:?} should be {}",
                status, expected
            );
        }
    }

    #[test]
    fn pkstatus_display_is_nonempty() {
        let statuses = [
            PKStatus::Success,
            PKStatus::InvalidInput,
            PKStatus::SchemeReadError,
            PKStatus::WitnessReadError,
            PKStatus::ProofError,
            PKStatus::SerializationError,
            PKStatus::Utf8Error,
            PKStatus::FileWriteError,
            PKStatus::CompilationError,
        ];
        for s in statuses {
            assert!(!s.to_string().is_empty());
        }
    }
}
