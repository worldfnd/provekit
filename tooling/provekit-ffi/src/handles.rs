//! Opaque handle types for FFI.
//!
//! These types wrap Rust structures in C-compatible handles for use across FFI
//! boundaries. Each handle owns the underlying Rust data and must be freed
//! using the corresponding `pk_*_free` function.

use provekit_common::{NoirProof, Prover, Verifier};

/// Opaque handle to a loaded prover.
///
/// The prover holds the proving key and can generate multiple proofs.
/// Must be freed with `pk_prover_free`.
#[repr(C)]
pub struct ProverHandle {
    pub(crate) inner: *mut Prover,
}

impl ProverHandle {
    /// Create a new handle from a Prover.
    pub fn new(prover: Prover) -> *mut Self {
        let handle = Box::new(Self {
            inner: Box::into_raw(Box::new(prover)),
        });
        Box::into_raw(handle)
    }

    /// Get a reference to the inner Prover.
    ///
    /// # Safety
    /// Caller must ensure handle is valid and not consumed.
    pub unsafe fn as_ref(&self) -> Option<&Prover> {
        if self.inner.is_null() {
            None
        } else {
            Some(&*self.inner)
        }
    }

    /// Get a mutable reference to the inner Prover.
    ///
    /// # Safety
    /// Caller must ensure handle is valid and not consumed.
    pub unsafe fn as_mut(&mut self) -> Option<&mut Prover> {
        if self.inner.is_null() {
            None
        } else {
            Some(&mut *self.inner)
        }
    }

    /// Take ownership of the inner Prover, consuming the handle.
    ///
    /// # Safety
    /// Caller must ensure handle is valid and owns the Prover.
    pub unsafe fn take(self) -> Option<Box<Prover>> {
        if self.inner.is_null() {
            None
        } else {
            Some(Box::from_raw(self.inner))
        }
    }

    /// Free the handle and its inner Prover.
    ///
    /// # Safety
    /// Caller must ensure handle is valid.
    pub unsafe fn free(handle: *mut Self) {
        if !handle.is_null() {
            let handle = Box::from_raw(handle);
            if !handle.inner.is_null() {
                drop(Box::from_raw(handle.inner));
            }
        }
    }
}

/// Opaque handle to a loaded verifier.
///
/// The verifier can only verify ONE proof (consumed after verify).
/// Must be freed with `pk_verifier_free` if verify was not called.
#[repr(C)]
pub struct VerifierHandle {
    pub(crate) inner: *mut Verifier,
    consumed: bool,
}

impl VerifierHandle {
    /// Create a new handle from a Verifier.
    pub fn new(verifier: Verifier) -> *mut Self {
        let handle = Box::new(Self {
            inner:    Box::into_raw(Box::new(verifier)),
            consumed: false,
        });
        Box::into_raw(handle)
    }

    /// Check if the verifier has been consumed.
    pub fn is_consumed(&self) -> bool {
        self.consumed
    }

    /// Get a mutable reference to the inner Verifier.
    ///
    /// # Safety
    /// Caller must ensure handle is valid.
    /// Note: Does NOT check consumed flag - caller should check is_consumed() first.
    pub unsafe fn as_mut(&mut self) -> Option<&mut Verifier> {
        if self.inner.is_null() {
            None
        } else {
            Some(&mut *self.inner)
        }
    }

    /// Mark the verifier as consumed.
    pub fn mark_consumed(&mut self) {
        self.consumed = true;
    }

    /// Free the handle and its inner Verifier.
    ///
    /// # Safety
    /// Caller must ensure handle is valid.
    pub unsafe fn free(handle: *mut Self) {
        if !handle.is_null() {
            let handle = Box::from_raw(handle);
            if !handle.inner.is_null() {
                drop(Box::from_raw(handle.inner));
            }
        }
    }
}

/// Opaque handle to a proof.
///
/// Holds the serialized proof data. Must be freed with `pk_proof_free`.
#[repr(C)]
pub struct ProofHandle {
    /// Pointer to boxed NoirProof
    inner: *mut NoirProof,
}

impl ProofHandle {
    /// Create a new handle from a NoirProof.
    pub fn new(proof: NoirProof) -> *mut Self {
        let handle = Box::new(Self {
            inner: Box::into_raw(Box::new(proof)),
        });
        Box::into_raw(handle)
    }

    /// Get a reference to the inner NoirProof.
    ///
    /// # Safety
    /// Caller must ensure handle is valid.
    pub unsafe fn as_ref(&self) -> Option<&NoirProof> {
        if self.inner.is_null() {
            None
        } else {
            Some(&*self.inner)
        }
    }

    /// Free the handle and its inner NoirProof.
    ///
    /// # Safety
    /// Caller must ensure handle is valid.
    pub unsafe fn free(handle: *mut Self) {
        if !handle.is_null() {
            let handle = Box::from_raw(handle);
            if !handle.inner.is_null() {
                drop(Box::from_raw(handle.inner));
            }
        }
    }
}
