//! Main FFI functions for ProveKit.

use {
    crate::{
        types::{PKBuf, PKError},
        utils::c_str_to_str,
    },
    anyhow::Result,
    provekit_common::{file::read, Prover},
    provekit_prover::Prove,
    std::{
        os::raw::{c_char, c_int},
        panic,
        path::Path,
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
                read(Path::new(prover_path)).map_err(|_| PKError::SchemeReadError)?;

            let proof = prover.prove(input_path).map_err(|_| PKError::ProofError)?;

            provekit_common::file::write(&proof, Path::new(out_path))
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
        let out_buf = match out_buf.as_mut() {
            Some(buf) => buf,
            None => return PKError::InvalidInput.into(),
        };

        *out_buf = PKBuf::empty();

        let result = (|| -> Result<Vec<u8>, PKError> {
            let prover_path = c_str_to_str(prover_path)?;
            let input_path = c_str_to_str(input_path)?;

            let prover: Prover =
                read(Path::new(prover_path)).map_err(|_| PKError::SchemeReadError)?;

            let proof = prover.prove(input_path).map_err(|_| PKError::ProofError)?;

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
    if !buf.ptr.is_null() && buf.len > 0 {
        drop(Vec::from_raw_parts(buf.ptr, buf.len, buf.len));
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
    // Initialize tracing/logging if needed
    // For now, we'll keep it simple and just return success
    PKError::Success.into()
}
