//! Utility functions for ProveKit FFI bindings.

use {
    crate::{ffi::set_last_error, types::PKStatus},
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
pub unsafe fn c_str_to_str(ptr: *const c_char) -> Result<String, PKStatus> {
    if ptr.is_null() {
        set_last_error("null pointer passed as C string".into());
        return Err(PKStatus::InvalidInput);
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map(|s| s.to_owned())
        .map_err(|e| {
            set_last_error(format!("invalid UTF-8 in C string: {e}"));
            PKStatus::Utf8Error
        })
}
