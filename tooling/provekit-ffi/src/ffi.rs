//! Main FFI functions for ProveKit.
//!
//! This module provides the C-compatible FFI functions for:
//! - Prover operations (load, prove, free)
//! - Verifier operations (load, verify, free)
//! - Proof utilities (get public inputs, serialize/deserialize)
//! - Memory management (free strings, buffers, bytes)

use {
    crate::{
        handles::{ProverHandle, VerifierHandle},
        types::{PKBuf, PKError},
        utils::{c_str_to_str, json_to_toml},
    },
    provekit_common::{
        file::{read, read_from_bytes, write_to_bytes},
        NoirProof, Prover, Verifier,
    },
    provekit_prover::Prove,
    provekit_verifier::Verify,
    std::{
        ffi::CString,
        os::raw::{c_char, c_int},
        panic,
        path::Path,
        ptr, slice,
    },
};

/// Catches panics and converts them to error codes to prevent unwinding across
/// FFI boundary.
#[inline]
fn catch_panic<F, T>(default: T, f: F) -> T
where
    F: FnOnce() -> T + panic::UnwindSafe,
{
    panic::catch_unwind(f).unwrap_or(default)
}

/// Set an error message string.
///
/// # Safety
/// Caller must ensure `error` is a valid pointer.
unsafe fn set_error(error: *mut *mut c_char, msg: &str) {
    if !error.is_null() {
        if let Ok(c_str) = CString::new(msg) {
            *error = c_str.into_raw();
        }
    }
}


// =============================================================================
// LEGACY FUNCTIONS (for backward compatibility)
// =============================================================================

/// Prove a Noir program and write the proof to a file.
///
/// # Arguments
///
/// * `prover_path` - Path to the prepared proof scheme (.pkp file)
/// * `input_path` - Path to the witness/input values (.toml file)
/// * `out_path` - Path where to write the proof file (.np or .json)
///
/// # Returns
///
/// Returns `PKError::Success` on success, or an appropriate error code on
/// failure.
///
/// # Safety
///
/// The caller must ensure that all path parameters are valid null-terminated C
/// strings.
#[no_mangle]
pub unsafe extern "C" fn pk_prove_to_file(
    prover_path: *const c_char,
    input_path: *const c_char,
    out_path: *const c_char,
) -> c_int {
    catch_panic(PKError::ProofError.into(), || {
        let result = (|| -> Result<(), PKError> {
            let prover_path = c_str_to_str(prover_path)?;
            let input_path = c_str_to_str(input_path)?;
            let out_path = c_str_to_str(out_path)?;

            let prover: Prover =
                read(Path::new(&prover_path)).map_err(|_| PKError::SchemeReadError)?;

            let proof = prover.prove(&input_path).map_err(|_| PKError::ProofError)?;

            provekit_common::file::write(&proof, Path::new(&out_path))
                .map_err(|_| PKError::FileWriteError)?;

            Ok(())
        })();

        match result {
            Ok(()) => PKError::Success.into(),
            Err(error) => error.into(),
        }
    })
}

/// Prove a Noir program and return the proof as JSON string.
///
/// This function is only available when the "json" feature is enabled.
///
/// # Arguments
///
/// * `scheme_path` - Path to the prepared proof scheme (.pkp file)
/// * `input_path` - Path to the witness/input values (.toml file)
/// * `out_buf` - Output buffer to store the JSON string
///
/// # Returns
///
/// Returns `PKError::Success` on success, or an appropriate error code on
/// failure. The caller must free the returned buffer using `pk_free_buf`.
///
/// # Safety
///
/// The caller must ensure that:
/// - `prover_path` and `input_path` are valid null-terminated C strings
/// - `out_buf` is a valid pointer to a `PKBuf` structure
/// - The returned buffer is freed using `pk_free_buf`
#[no_mangle]
pub unsafe extern "C" fn pk_prove_to_json(
    prover_path: *const c_char,
    input_path: *const c_char,
    out_buf: *mut PKBuf,
) -> c_int {
    if out_buf.is_null() {
        return PKError::InvalidInput.into();
    }

    catch_panic(PKError::ProofError.into(), || {
        // Safety: out_buf is guaranteed non-null by the check above
        let out_buf = &mut *out_buf;

        *out_buf = PKBuf::empty();

        let result = (|| -> Result<Vec<u8>, PKError> {
            let prover_path = c_str_to_str(prover_path)?;
            let input_path = c_str_to_str(input_path)?;

            let prover: Prover =
                read(Path::new(&prover_path)).map_err(|_| PKError::SchemeReadError)?;

            let proof = prover.prove(&input_path).map_err(|_| PKError::ProofError)?;

            let json_string =
                serde_json::to_string(&proof).map_err(|_| PKError::SerializationError)?;

            Ok(json_string.into_bytes())
        })();

        match result {
            Ok(json_bytes) => {
                *out_buf = PKBuf::from_vec(json_bytes);
                PKError::Success.into()
            }
            Err(error) => error.into(),
        }
    })
}

/// Free a buffer allocated by ProveKit FFI functions.
///
/// # Arguments
///
/// * `buf` - The buffer to free
///
/// # Safety
///
/// The caller must ensure that:
/// - The buffer was allocated by a ProveKit FFI function
/// - The buffer is not used after calling this function
/// - This function is called exactly once for each allocated buffer
#[no_mangle]
pub unsafe extern "C" fn pk_free_buf(buf: PKBuf) {
    if !buf.ptr.is_null() && buf.cap > 0 {
        drop(Vec::from_raw_parts(buf.ptr, buf.len, buf.cap));
    }
}

/// Initialize the ProveKit library.
///
/// This function should be called once before using any other ProveKit
/// functions. It sets up logging and other global state.
///
/// # Returns
///
/// Returns `PKError::Success` on success.
#[no_mangle]
pub extern "C" fn pk_init() -> c_int {
    // TODO: Initialize tracing/logging for FFI consumers.
    provekit_common::register_ntt();
    PKError::Success.into()
}

/// Configure the mmap-based memory allocator.
///
/// MUST be called before pk_init() and before any allocations occur.
///
/// # Arguments
///
/// * `ram_limit_bytes` - Maximum RAM to use before swapping to file (must be >
///   0)
/// * `use_file_backed` - Whether to use file-backed mmap when over RAM limit
/// * `swap_file_path` - Path to swap directory (NULL = use system temp dir)
///
/// # Returns
///
/// Returns `PKError::Success` or `PKError::InvalidInput` if ram_limit_bytes is
/// 0.
///
/// # Safety
///
/// The caller must ensure that `swap_file_path` is either NULL or a valid
/// null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pk_configure_memory(
    ram_limit_bytes: usize,
    use_file_backed: bool,
    swap_file_path: *const c_char,
) -> c_int {
    if ram_limit_bytes == 0 {
        return PKError::InvalidInput.into();
    }

    if crate::mmap_allocator::configure_allocator(ram_limit_bytes, use_file_backed, swap_file_path)
    {
        PKError::Success.into()
    } else {
        PKError::InvalidInput.into()
    }
}

/// Get current memory statistics.
///
/// # Arguments
///
/// * `ram_used` - Output: current RAM usage in bytes (can be NULL)
/// * `swap_used` - Output: current swap usage in bytes (can be NULL)
/// * `peak_ram` - Output: peak RAM usage in bytes (can be NULL)
///
/// # Returns
///
/// Returns `PKError::Success`.
///
/// # Safety
///
/// The caller must ensure that all non-NULL pointers are valid.
#[no_mangle]
pub unsafe extern "C" fn pk_get_memory_stats(
    ram_used: *mut usize,
    swap_used: *mut usize,
    peak_ram: *mut usize,
) -> c_int {
    let (ram, swap, peak) = crate::mmap_allocator::get_stats();

    if !ram_used.is_null() {
        *ram_used = ram;
    }
    if !swap_used.is_null() {
        *swap_used = swap;
    }
    if !peak_ram.is_null() {
        *peak_ram = peak;
    }

    PKError::Success.into()
}

// =============================================================================
// PROVER FUNCTIONS
// =============================================================================

/// Load a prover from PKP data in memory.
///
/// # Arguments
///
/// * `data` - Pointer to PKP data.
/// * `len` - Length of data in bytes.
/// * `error` - Output: error message if failed (caller must free with
///   `pk_free_string`).
///
/// # Returns
///
/// Prover handle on success, NULL on failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `data` is valid for reads of `len` bytes
/// - `error` is either NULL or a valid pointer
#[no_mangle]
pub unsafe extern "C" fn pk_prover_load(
    data: *const u8,
    len: usize,
    error: *mut *mut c_char,
) -> *mut ProverHandle {
    catch_panic(ptr::null_mut(), || {
        // Validate inputs
        if data.is_null() || len == 0 {
            set_error(error, "data is null or empty");
            return ptr::null_mut();
        }

        // Convert to slice
        let bytes = slice::from_raw_parts(data, len);

        // Deserialize prover
        let prover: Prover = match read_from_bytes(bytes) {
            Ok(p) => p,
            Err(e) => {
                set_error(error, &format!("Failed to load prover: {}", e));
                return ptr::null_mut();
            }
        };

        ProverHandle::new(prover)
    })
}

/// Load a prover from a PKP file.
///
/// # Arguments
///
/// * `path` - Null-terminated path to .pkp file.
/// * `error` - Output: error message if failed.
///
/// # Returns
///
/// Prover handle on success, NULL on failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `path` is a valid null-terminated C string
/// - `error` is either NULL or a valid pointer
#[no_mangle]
pub unsafe extern "C" fn pk_prover_load_file(
    path: *const c_char,
    error: *mut *mut c_char,
) -> *mut ProverHandle {
    catch_panic(ptr::null_mut(), || {
        // Validate and convert path
        let path_str = match c_str_to_str(path) {
            Ok(s) => s,
            Err(_) => {
                set_error(error, "Invalid path");
                return ptr::null_mut();
            }
        };

        // Load prover from file
        let prover: Prover = match read(Path::new(&path_str)) {
            Ok(p) => p,
            Err(e) => {
                set_error(error, &format!("Failed to load prover: {}", e));
                return ptr::null_mut();
            }
        };

        ProverHandle::new(prover)
    })
}

/// Generate a proof using the prover.
///
/// **Note**: This function consumes the prover. After calling this function,
/// the prover handle is invalid and should not be used again. Call
/// `pk_prover_free` to clean up.
///
/// # Arguments
///
/// * `prover` - Prover handle (consumed after this call).
/// * `inputs_json` - JSON string of input values.
/// * `proof_out` - Output: pointer to proof data (caller must free with
///   `pk_free_bytes`).
/// * `proof_len` - Output: length of proof data.
/// * `error` - Output: error message if failed.
///
/// # Returns
///
/// 0 on success, non-zero on failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `prover` is a valid ProverHandle
/// - `inputs_json` is a valid null-terminated JSON string
/// - `proof_out` and `proof_len` are valid pointers
/// - The returned proof data is freed using `pk_free_bytes`
/// - The prover handle is not used after this call
#[no_mangle]
pub unsafe extern "C" fn pk_prover_prove(
    prover: *mut ProverHandle,
    inputs_json: *const c_char,
    proof_out: *mut *mut u8,
    proof_len: *mut usize,
    error: *mut *mut c_char,
) -> c_int {
    catch_panic(PKError::ProofError.into(), || {
        // Validate inputs
        if prover.is_null() {
            set_error(error, "prover is null");
            return PKError::InvalidInput.into();
        }
        if proof_out.is_null() || proof_len.is_null() {
            set_error(error, "output pointers are null");
            return PKError::InvalidInput.into();
        }

        // Initialize outputs
        *proof_out = ptr::null_mut();
        *proof_len = 0;

        let json_str = match c_str_to_str(inputs_json) {
            Ok(s) => s,
            Err(_) => {
                set_error(error, "Invalid JSON input");
                return PKError::InvalidInput.into();
            }
        };

        // Borrow the prover (don't consume - allow multiple prove calls)
        let handle_ref = &mut *prover;
        let prover_ref = match handle_ref.as_ref() {
            Some(p) => p,
            None => {
                set_error(error, "Prover handle is invalid");
                return PKError::InvalidInput.into();
            }
        };

        // Clone the prover since prove() consumes self
        let prover_clone = prover_ref.clone();

        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(format!("pk_inputs_{}.toml", std::process::id()));

        // Convert JSON to TOML
        let toml_str = match json_to_toml(&json_str) {
            Ok(s) => s,
            Err(e) => {
                set_error(error, &format!("Failed to convert JSON to TOML: {}", e));
                return PKError::InvalidInput.into();
            }
        };

        if let Err(e) = std::fs::write(&temp_path, &toml_str) {
            set_error(error, &format!("Failed to write temp file: {}", e));
            return PKError::FileWriteError.into();
        }

        // Generate proof
        let proof = match prover_clone.prove(&temp_path) {
            Ok(p) => p,
            Err(e) => {
                let _ = std::fs::remove_file(&temp_path);
                set_error(error, &format!("Failed to generate proof: {}", e));
                return PKError::ProofError.into();
            }
        };

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_path);

        // Serialize proof to bytes
        let proof_bytes = match write_to_bytes(&proof) {
            Ok(b) => b,
            Err(e) => {
                set_error(error, &format!("Failed to serialize proof: {}", e));
                return PKError::SerializationError.into();
            }
        };

        // Transfer ownership to caller
        let mut bytes_vec = proof_bytes;
        *proof_out = bytes_vec.as_mut_ptr();
        *proof_len = bytes_vec.len();
        std::mem::forget(bytes_vec);

        PKError::Success.into()
    })
}

/// Free a prover handle.
///
/// # Safety
///
/// The caller must ensure that:
/// - `prover` was allocated by `pk_prover_load` or `pk_prover_load_file`
/// - `prover` is not used after this call
#[no_mangle]
pub unsafe extern "C" fn pk_prover_free(prover: *mut ProverHandle) {
    if !prover.is_null() {
        ProverHandle::free(prover);
    }
}

// =============================================================================
// VERIFIER FUNCTIONS
// =============================================================================

/// Load a verifier from PKV data in memory.
///
/// # Arguments
///
/// * `data` - Pointer to PKV data.
/// * `len` - Length of data in bytes.
/// * `error` - Output: error message if failed (caller must free with
///   `pk_free_string`).
///
/// # Returns
///
/// Verifier handle on success, NULL on failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `data` is valid for reads of `len` bytes
/// - `error` is either NULL or a valid pointer
#[no_mangle]
pub unsafe extern "C" fn pk_verifier_load(
    data: *const u8,
    len: usize,
    error: *mut *mut c_char,
) -> *mut VerifierHandle {
    catch_panic(ptr::null_mut(), || {
        // Validate inputs
        if data.is_null() || len == 0 {
            set_error(error, "data is null or empty");
            return ptr::null_mut();
        }

        // Convert to slice
        let bytes = slice::from_raw_parts(data, len);

        // Deserialize verifier
        let verifier: Verifier = match read_from_bytes(bytes) {
            Ok(v) => v,
            Err(e) => {
                set_error(error, &format!("Failed to load verifier: {}", e));
                return ptr::null_mut();
            }
        };

        VerifierHandle::new(verifier)
    })
}

/// Load a verifier from a PKV file.
///
/// # Arguments
///
/// * `path` - Null-terminated path to .pkv file.
/// * `error` - Output: error message if failed.
///
/// # Returns
///
/// Verifier handle on success, NULL on failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `path` is a valid null-terminated C string
/// - `error` is either NULL or a valid pointer
#[no_mangle]
pub unsafe extern "C" fn pk_verifier_load_file(
    path: *const c_char,
    error: *mut *mut c_char,
) -> *mut VerifierHandle {
    catch_panic(ptr::null_mut(), || {
        // Validate and convert path
        let path_str = match c_str_to_str(path) {
            Ok(s) => s,
            Err(_) => {
                set_error(error, "Invalid path");
                return ptr::null_mut();
            }
        };

        // Load verifier from file
        let verifier: Verifier = match read(Path::new(&path_str)) {
            Ok(v) => v,
            Err(e) => {
                set_error(error, &format!("Failed to load verifier: {}", e));
                return ptr::null_mut();
            }
        };

        VerifierHandle::new(verifier)
    })
}

/// Verify a proof. Consumes the verifier.
///
/// # Arguments
///
/// * `verifier` - Verifier handle (consumed after call).
/// * `proof` - Pointer to proof data.
/// * `proof_len` - Length of proof data.
/// * `error` - Output: error message if failed.
///
/// # Returns
///
/// 0 if valid, non-zero on error or invalid proof.
///
/// # Safety
///
/// The caller must ensure that:
/// - `verifier` is a valid VerifierHandle
/// - `proof` is valid for reads of `proof_len` bytes
/// - The verifier is not used after this call
#[no_mangle]
pub unsafe extern "C" fn pk_verifier_verify(
    verifier: *mut VerifierHandle,
    proof: *const u8,
    proof_len: usize,
    error: *mut *mut c_char,
) -> c_int {
    catch_panic(PKError::ProofError.into(), || {
        // Validate inputs
        if verifier.is_null() {
            set_error(error, "verifier is null");
            return PKError::InvalidInput.into();
        }
        if proof.is_null() || proof_len == 0 {
            set_error(error, "proof is null or empty");
            return PKError::InvalidInput.into();
        }

        let handle = &mut *verifier;

        // Check if already consumed
        if handle.is_consumed() {
            set_error(error, "Verifier has already been consumed");
            return PKError::VerifierConsumed.into();
        }

        // Mark as consumed immediately to prevent double-use
        handle.mark_consumed();

        // Deserialize proof
        let proof_bytes = slice::from_raw_parts(proof, proof_len);
        let noir_proof: NoirProof = match read_from_bytes(proof_bytes) {
            Ok(p) => p,
            Err(e) => {
                set_error(error, &format!("Failed to deserialize proof: {}", e));
                return PKError::DeserializationError.into();
            }
        };

        // Get mutable reference to verifier
        let verifier_ref = match handle.as_mut() {
            Some(v) => v,
            None => {
                set_error(error, "Verifier handle is invalid");
                return PKError::InvalidInput.into();
            }
        };

        // Verify the proof
        match verifier_ref.verify(&noir_proof) {
            Ok(()) => PKError::Success.into(),
            Err(e) => {
                set_error(error, &format!("Verification failed: {}", e));
                PKError::VerificationFailed.into()
            }
        }
    })
}

/// Free a verifier handle (only needed if verify was not called).
///
/// # Safety
///
/// The caller must ensure that:
/// - `verifier` was allocated by `pk_verifier_load` or `pk_verifier_load_file`
/// - `verifier` is not used after this call
#[no_mangle]
pub unsafe extern "C" fn pk_verifier_free(verifier: *mut VerifierHandle) {
    if !verifier.is_null() {
        VerifierHandle::free(verifier);
    }
}

// =============================================================================
// PROOF UTILITIES
// =============================================================================

/// Extract public inputs from a proof as JSON.
///
/// # Arguments
///
/// * `proof` - Pointer to proof data.
/// * `proof_len` - Length of proof data.
/// * `json_out` - Output: JSON string of public inputs (caller must free with
///   `pk_free_string`).
/// * `error` - Output: error message if failed.
///
/// # Returns
///
/// 0 on success, non-zero on failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `proof` is valid for reads of `proof_len` bytes
/// - `json_out` is a valid pointer
#[no_mangle]
pub unsafe extern "C" fn pk_proof_get_public_inputs(
    proof: *const u8,
    proof_len: usize,
    json_out: *mut *mut c_char,
    error: *mut *mut c_char,
) -> c_int {
    catch_panic(PKError::ProofError.into(), || {
        // Validate inputs
        if proof.is_null() || proof_len == 0 {
            set_error(error, "proof is null or empty");
            return PKError::InvalidInput.into();
        }
        if json_out.is_null() {
            set_error(error, "json_out is null");
            return PKError::InvalidInput.into();
        }

        // Initialize output
        *json_out = ptr::null_mut();

        // Deserialize proof
        let proof_bytes = slice::from_raw_parts(proof, proof_len);
        let noir_proof: NoirProof = match read_from_bytes(proof_bytes) {
            Ok(p) => p,
            Err(e) => {
                set_error(error, &format!("Failed to deserialize proof: {}", e));
                return PKError::DeserializationError.into();
            }
        };

        // Serialize public inputs to JSON
        let json_str = match serde_json::to_string(&noir_proof.public_inputs) {
            Ok(s) => s,
            Err(e) => {
                set_error(error, &format!("Failed to serialize public inputs: {}", e));
                return PKError::SerializationError.into();
            }
        };

        // Convert to C string
        match CString::new(json_str) {
            Ok(c_str) => {
                *json_out = c_str.into_raw();
                PKError::Success.into()
            }
            Err(_) => {
                set_error(error, "Public inputs contain null bytes");
                PKError::SerializationError.into()
            }
        }
    })
}

// =============================================================================
// MEMORY MANAGEMENT
// =============================================================================

/// Free a string allocated by ProveKit.
///
/// # Safety
///
/// The caller must ensure that:
/// - `str` was allocated by a ProveKit FFI function
/// - `str` is not used after this call
#[no_mangle]
pub unsafe extern "C" fn pk_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Free a byte buffer allocated by ProveKit.
///
/// # Arguments
///
/// * `bytes` - Pointer to the byte buffer.
/// * `len` - Length of the buffer.
///
/// # Safety
///
/// The caller must ensure that:
/// - `bytes` was allocated by a ProveKit FFI function
/// - `bytes` is not used after this call
#[no_mangle]
pub unsafe extern "C" fn pk_free_bytes(bytes: *mut u8, len: usize) {
    if !bytes.is_null() && len > 0 {
        drop(Vec::from_raw_parts(bytes, len, len));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::path::PathBuf;

    fn test_fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../noir-examples/basic-2")
    }

    fn prover_path() -> PathBuf {
        test_fixtures_dir().join("prover.pkp")
    }

    fn verifier_path() -> PathBuf {
        test_fixtures_dir().join("verifier.pkv")
    }

    fn proof_path() -> PathBuf {
        test_fixtures_dir().join("proof.np")
    }

    #[test]
    fn test_pk_init() {
        let result = pk_init();
        assert_eq!(result, PKError::Success as i32);
    }

    #[test]
    fn test_prover_load_file() {
        pk_init();

        let path = prover_path();
        if !path.exists() {
            eprintln!("Skipping test: {:?} not found", path);
            return;
        }

        let path_cstr = CString::new(path.to_str().unwrap()).unwrap();
        let mut error: *mut c_char = std::ptr::null_mut();

        unsafe {
            let handle = pk_prover_load_file(path_cstr.as_ptr(), &mut error);
            if handle.is_null() && !error.is_null() {
                let err_str = std::ffi::CStr::from_ptr(error).to_str().unwrap();
                panic!("Failed to load prover: {}", err_str);
            }
            assert!(!handle.is_null(), "Failed to load prover (no error msg)");
            pk_prover_free(handle);
        }
    }

    #[test]
    fn test_prover_load_from_bytes() {
        pk_init();

        let path = prover_path();
        if !path.exists() {
            eprintln!("Skipping test: {:?} not found", path);
            return;
        }

        let bytes = std::fs::read(&path).unwrap();
        let mut error: *mut c_char = std::ptr::null_mut();

        unsafe {
            let handle = pk_prover_load(bytes.as_ptr(), bytes.len(), &mut error);
            assert!(!handle.is_null(), "Failed to load prover from bytes");
            assert!(error.is_null(), "Unexpected error");
            pk_prover_free(handle);
        }
    }

    #[test]
    fn test_verifier_load_file() {
        pk_init();

        let path = verifier_path();
        if !path.exists() {
            eprintln!("Skipping test: {:?} not found", path);
            return;
        }

        let path_cstr = CString::new(path.to_str().unwrap()).unwrap();
        let mut error: *mut c_char = std::ptr::null_mut();

        unsafe {
            let handle = pk_verifier_load_file(path_cstr.as_ptr(), &mut error);
            assert!(!handle.is_null(), "Failed to load verifier");
            assert!(error.is_null(), "Unexpected error");
            pk_verifier_free(handle);
        }
    }

    #[test]
    fn test_verifier_load_from_bytes() {
        pk_init();

        let path = verifier_path();
        if !path.exists() {
            eprintln!("Skipping test: {:?} not found", path);
            return;
        }

        let bytes = std::fs::read(&path).unwrap();
        let mut error: *mut c_char = std::ptr::null_mut();

        unsafe {
            let handle = pk_verifier_load(bytes.as_ptr(), bytes.len(), &mut error);
            assert!(!handle.is_null(), "Failed to load verifier from bytes");
            assert!(error.is_null(), "Unexpected error");
            pk_verifier_free(handle);
        }
    }

    #[test]
    fn test_prover_load_invalid_data() {
        pk_init();

        let invalid_data = vec![0u8; 100];
        let mut error: *mut c_char = std::ptr::null_mut();

        unsafe {
            let handle = pk_prover_load(invalid_data.as_ptr(), invalid_data.len(), &mut error);
            assert!(handle.is_null(), "Should fail with invalid data");
            assert!(!error.is_null(), "Should have error message");
            pk_free_string(error);
        }
    }

    #[test]
    fn test_verifier_load_invalid_data() {
        pk_init();

        let invalid_data = vec![0u8; 100];
        let mut error: *mut c_char = std::ptr::null_mut();

        unsafe {
            let handle = pk_verifier_load(invalid_data.as_ptr(), invalid_data.len(), &mut error);
            assert!(handle.is_null(), "Should fail with invalid data");
            assert!(!error.is_null(), "Should have error message");
            pk_free_string(error);
        }
    }

    #[test]
    fn test_prover_load_null_data() {
        pk_init();

        let mut error: *mut c_char = std::ptr::null_mut();

        unsafe {
            let handle = pk_prover_load(std::ptr::null(), 0, &mut error);
            assert!(handle.is_null(), "Should fail with null data");
        }
    }

    #[test]
    fn test_verify_existing_proof() {
        pk_init();

        let verifier_p = verifier_path();
        let proof_p = proof_path();

        if !verifier_p.exists() || !proof_p.exists() {
            eprintln!("Skipping test: fixtures not found");
            return;
        }

        let verifier_bytes = std::fs::read(&verifier_p).unwrap();
        let proof_bytes = std::fs::read(&proof_p).unwrap();
        let mut error: *mut c_char = std::ptr::null_mut();

        unsafe {
            let verifier = pk_verifier_load(
                verifier_bytes.as_ptr(),
                verifier_bytes.len(),
                &mut error,
            );
            assert!(!verifier.is_null(), "Failed to load verifier");

            let result = pk_verifier_verify(
                verifier,
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                &mut error,
            );

            if result != PKError::Success as i32 && !error.is_null() {
                let err_msg = std::ffi::CStr::from_ptr(error).to_str().unwrap();
                panic!("Verification failed with error code {}: {}", result, err_msg);
            }
            assert_eq!(
                result,
                PKError::Success as i32,
                "Verification should succeed"
            );

            pk_verifier_free(verifier);
        }
    }

    #[test]
    fn test_verifier_consumed_error() {
        pk_init();

        let verifier_p = verifier_path();
        let proof_p = proof_path();

        if !verifier_p.exists() || !proof_p.exists() {
            eprintln!("Skipping test: fixtures not found");
            return;
        }

        let verifier_bytes = std::fs::read(&verifier_p).unwrap();
        let proof_bytes = std::fs::read(&proof_p).unwrap();
        let mut error: *mut c_char = std::ptr::null_mut();

        unsafe {
            let verifier = pk_verifier_load(
                verifier_bytes.as_ptr(),
                verifier_bytes.len(),
                &mut error,
            );
            assert!(!verifier.is_null());

            let result1 = pk_verifier_verify(
                verifier,
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                &mut error,
            );
            assert_eq!(result1, PKError::Success as i32);

            let result2 = pk_verifier_verify(
                verifier,
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                &mut error,
            );
            assert_eq!(
                result2,
                PKError::VerifierConsumed as i32,
                "Second verify should fail with VerifierConsumed"
            );

            if !error.is_null() {
                pk_free_string(error);
            }
            pk_verifier_free(verifier);
        }
    }

    #[test]
    fn test_proof_get_public_inputs() {
        pk_init();

        let proof_p = proof_path();
        if !proof_p.exists() {
            eprintln!("Skipping test: {:?} not found", proof_p);
            return;
        }

        let proof_bytes = std::fs::read(&proof_p).unwrap();
        let mut json_out: *mut c_char = std::ptr::null_mut();
        let mut error: *mut c_char = std::ptr::null_mut();

        unsafe {
            let result = pk_proof_get_public_inputs(
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                &mut json_out,
                &mut error,
            );

            assert_eq!(result, PKError::Success as i32);
            assert!(!json_out.is_null(), "Should return JSON");

            let json_str = std::ffi::CStr::from_ptr(json_out).to_str().unwrap();
            assert!(json_str.starts_with('[') || json_str.starts_with('{'));

            pk_free_string(json_out);
        }
    }

    #[test]
    fn test_read_from_bytes_proof() {
        use provekit_common::file::{read, read_from_bytes};
        use provekit_common::NoirProof;

        let proof_p = proof_path();
        if !proof_p.exists() {
            eprintln!("Skipping test: {:?} not found", proof_p);
            return;
        }

        // Test 1: File-based read (should work)
        let file_proof = read::<NoirProof>(&proof_p).expect("File-based read should work");
        println!("File-based read: SUCCESS! Public inputs: {}", file_proof.public_inputs.len());

        // Test 2: Byte-based read
        let bytes = std::fs::read(&proof_p).unwrap();
        println!("Read {} bytes from proof.np", bytes.len());
        println!("First 32 bytes: {:02X?}", &bytes[..32.min(bytes.len())]);

        match read_from_bytes::<NoirProof>(&bytes) {
            Ok(proof) => {
                println!("Bytes-based read: SUCCESS! Public inputs: {}", proof.public_inputs.len());
                assert_eq!(proof.public_inputs.len(), file_proof.public_inputs.len());
            }
            Err(e) => {
                panic!("Bytes-based read FAILED: {:?}", e);
            }
        }
    }

    /// End-to-end test: Load PKP → Generate Proof → Write to File → Load PKV → Verify Proof
    #[test]
    fn test_end_to_end_prove_and_verify() {
        pk_init();

        // Use basic-2 example which has pre-generated PKP and PKV
        let base_dir = test_fixtures_dir().parent().unwrap().join("basic-2");
        let pkp_path = base_dir.join("prover.pkp");
        let pkv_path = base_dir.join("verifier.pkv");

        if !pkp_path.exists() || !pkv_path.exists() {
            eprintln!("Skipping test: basic-2 fixtures not found at {:?}", base_dir);
            return;
        }

        // Create temp file for proof output
        let temp_dir = std::env::temp_dir();
        let proof_output_path = temp_dir.join("test_e2e_proof.np");

        // Clean up any existing file
        let _ = std::fs::remove_file(&proof_output_path);

        unsafe {
            // =========================================
            // Step 1: Load Prover from PKP file
            // =========================================
            let pkp_cstr = CString::new(pkp_path.to_str().unwrap()).unwrap();
            let mut error: *mut c_char = std::ptr::null_mut();

            let prover = pk_prover_load_file(pkp_cstr.as_ptr(), &mut error);
            assert!(!prover.is_null(), "Failed to load prover: {:?}", 
                error.as_ref().map(|e| std::ffi::CStr::from_ptr(e).to_str().unwrap()));
            println!("✓ Step 1: Loaded prover from {:?}", pkp_path);

            // =========================================
            // Step 2: Generate proof with inputs (JSON format)
            // =========================================
            let inputs_json = r#"{
                "plains": [1, 2],
                "a": 1,
                "b": 2,
                "c": 3,
                "d": 5,
                "x": 0,
                "result": "0x0e90c132311e864e0c8bca37976f28579a2dd9436bbc11326e21ec7c00cea5b2"
            }"#;
            let inputs_cstr = CString::new(inputs_json).unwrap();

            let mut proof_ptr: *mut u8 = std::ptr::null_mut();
            let mut proof_len: usize = 0;
            error = std::ptr::null_mut();

            let result = pk_prover_prove(
                prover,
                inputs_cstr.as_ptr(),
                &mut proof_ptr,
                &mut proof_len,
                &mut error,
            );

            assert_eq!(result, PKError::Success as i32, "Prove failed: {:?}",
                error.as_ref().map(|e| std::ffi::CStr::from_ptr(e).to_str().unwrap()));
            assert!(!proof_ptr.is_null(), "Proof pointer is null");
            assert!(proof_len > 0, "Proof length is 0");
            println!("✓ Step 2: Generated proof ({} bytes)", proof_len);

            // =========================================
            // Step 3: Write proof to file
            // =========================================
            let proof_bytes = std::slice::from_raw_parts(proof_ptr, proof_len);
            std::fs::write(&proof_output_path, proof_bytes)
                .expect("Failed to write proof to file");
            println!("✓ Step 3: Wrote proof to {:?}", proof_output_path);

            // Free the proof bytes (we've copied them to file)
            pk_free_bytes(proof_ptr, proof_len);

            // Free the prover handle
            pk_prover_free(prover);

            // =========================================
            // Step 4: Load Verifier from PKV file
            // =========================================
            let pkv_cstr = CString::new(pkv_path.to_str().unwrap()).unwrap();
            error = std::ptr::null_mut();

            let verifier = pk_verifier_load_file(pkv_cstr.as_ptr(), &mut error);
            assert!(!verifier.is_null(), "Failed to load verifier: {:?}",
                error.as_ref().map(|e| std::ffi::CStr::from_ptr(e).to_str().unwrap()));
            println!("✓ Step 4: Loaded verifier from {:?}", pkv_path);

            // =========================================
            // Step 5: Read proof from file and verify
            // =========================================
            let proof_from_file = std::fs::read(&proof_output_path)
                .expect("Failed to read proof from file");
            println!("✓ Step 5a: Read proof from file ({} bytes)", proof_from_file.len());

            error = std::ptr::null_mut();
            let verify_result = pk_verifier_verify(
                verifier,
                proof_from_file.as_ptr(),
                proof_from_file.len(),
                &mut error,
            );

            assert_eq!(verify_result, PKError::Success as i32, "Verification failed: {:?}",
                error.as_ref().map(|e| std::ffi::CStr::from_ptr(e).to_str().unwrap()));
            println!("✓ Step 5b: Proof verified successfully!");

            // Clean up
            pk_verifier_free(verifier);
            let _ = std::fs::remove_file(&proof_output_path);

            println!("\n=== END-TO-END TEST PASSED ===");
            println!("  PKP loaded: {:?}", pkp_path);
            println!("  PKV loaded: {:?}", pkv_path);
            println!("  Proof generated and verified successfully!");
        }
    }
}
