use {
    mobench_sdk::{run_benchmark, BenchSpec, MobenchBuf},
    std::{
        any::Any,
        cell::RefCell,
        ffi::CString,
        os::raw::c_char,
        panic::{catch_unwind, AssertUnwindSafe},
        slice,
    },
};

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

fn set_last_error(message: impl AsRef<str>) {
    let sanitized = message.as_ref().replace('\0', "\\0");
    let value = CString::new(sanitized).unwrap_or_default();
    LAST_ERROR.with(|error| *error.borrow_mut() = value);
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else {
        "benchmark panicked with a non-string payload".to_owned()
    }
}

/// Runs a Mobench benchmark through the native JSON C ABI.
///
/// This mirrors Mobench 0.1.48's ABI while preserving the panic payload in
/// `mobench_last_error_message`, which is required to diagnose device-only
/// setup failures.
///
/// # Safety
///
/// `spec_ptr` must be valid for `spec_len` readable bytes when non-null.
/// `out` must point to one writable [`MobenchBuf`].
#[no_mangle]
pub unsafe extern "C" fn mobench_run_benchmark_json(
    spec_ptr: *const u8,
    spec_len: usize,
    out: *mut MobenchBuf,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        if out.is_null() {
            return Err("output buffer pointer must not be null".to_owned());
        }
        // SAFETY: The caller guarantees that `out` is writable.
        unsafe { *out = MobenchBuf::default() };
        if spec_len > 0 && spec_ptr.is_null() {
            return Err("spec pointer must not be null when spec length is non-zero".to_owned());
        }
        let spec_bytes = if spec_len == 0 {
            &[]
        } else {
            // SAFETY: The caller guarantees `spec_ptr` is readable for
            // `spec_len` bytes.
            unsafe { slice::from_raw_parts(spec_ptr, spec_len) }
        };
        let spec: BenchSpec = serde_json::from_slice(spec_bytes)
            .map_err(|error| format!("failed to parse BenchSpec JSON: {error}"))?;
        let report = run_benchmark(spec).map_err(|error| error.to_string())?;
        let mut bytes = serde_json::to_vec(&report)
            .map_err(|error| format!("failed to serialize benchmark report: {error}"))?;
        let buffer = MobenchBuf {
            ptr: bytes.as_mut_ptr(),
            len: bytes.len(),
            cap: bytes.capacity(),
        };
        std::mem::forget(bytes);
        // SAFETY: The caller guarantees that `out` is writable.
        unsafe { *out = buffer };
        Ok(())
    }));
    match result {
        Ok(Ok(())) => {
            set_last_error("");
            0
        }
        Ok(Err(error)) => {
            set_last_error(error);
            1
        }
        Err(payload) => {
            set_last_error(panic_message(payload));
            2
        }
    }
}

/// Frees a buffer returned by [`mobench_run_benchmark_json`].
///
/// # Safety
///
/// `buffer` must be null or point to an initialized [`MobenchBuf`]. A non-null
/// allocation must have been returned by this module and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn mobench_free_buf(buffer: *mut MobenchBuf) {
    if buffer.is_null() {
        return;
    }
    // SAFETY: The caller guarantees that `buffer` is writable.
    let buffer = unsafe { &mut *buffer };
    if !buffer.ptr.is_null() {
        let (data, len, cap) = (buffer.ptr, buffer.len, buffer.cap);
        *buffer = MobenchBuf::default();
        // SAFETY: This allocation was created from a Vec with these exact
        // pointer, length, and capacity values.
        unsafe { drop(Vec::from_raw_parts(data, len, cap)) };
    } else {
        *buffer = MobenchBuf::default();
    }
}

/// Returns the most recent C-ABI error message for this thread.
#[no_mangle]
pub extern "C" fn mobench_last_error_message() -> *const c_char {
    LAST_ERROR.with(|error| error.borrow().as_ptr())
}
