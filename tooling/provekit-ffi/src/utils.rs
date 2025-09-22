//! Utility functions for ProveKit FFI bindings.

use {
    crate::types::PKError,
    anyhow::Result,
    std::{ffi::CStr, os::raw::c_char},
};

/// Internal helper to convert C string to Rust string
///
/// # Safety
///
/// The caller must ensure that `ptr` is a valid null-terminated C string.
pub unsafe fn c_str_to_str(ptr: *const c_char) -> Result<&'static str, PKError> {
    if ptr.is_null() {
        return Err(PKError::InvalidInput);
    }
    CStr::from_ptr(ptr).to_str().map_err(|_| PKError::Utf8Error)
}
