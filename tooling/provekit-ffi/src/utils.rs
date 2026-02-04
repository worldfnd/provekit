//! Utility functions for ProveKit FFI bindings.

use {
    crate::types::PKError,
    anyhow::Result,
    std::{ffi::CStr, os::raw::c_char},
};

/// Internal helper to convert C string to owned Rust String.
///
/// This function copies the C string to avoid lifetime issues where the caller
/// might deallocate the C string while Rust code still holds a reference.
///
/// # Safety
///
/// The caller must ensure that `ptr` is a valid null-terminated C string
/// that remains valid for the duration of this function call.
pub unsafe fn c_str_to_str(ptr: *const c_char) -> Result<String, PKError> {
    if ptr.is_null() {
        return Err(PKError::InvalidInput);
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map(|s| s.to_owned())
        .map_err(|_| PKError::Utf8Error)
}
