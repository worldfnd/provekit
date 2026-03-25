//! Handle-based FFI functions for ProveKit.
//!
//! All functions use opaque `PKProver` / `PKVerifier` handles instead of file
//! paths. Proofs are always returned as bytes in a `PKBuf`.

use {
    crate::{
        types::{PKBuf, PKError, PKProver, PKVerifier},
        utils::c_str_to_str,
    },
    noirc_abi::input_parser::Format,
    provekit_common::{file, HashConfig, NoirProof, Prover, Verifier},
    provekit_prover::Prove,
    provekit_r1cs_compiler::NoirCompiler,
    provekit_verifier::Verify,
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

/// Initialize the ProveKit library.
///
/// Must be called once before using any other ProveKit functions.
#[no_mangle]
pub extern "C" fn pk_init() -> c_int {
    provekit_common::register_ntt();
    PKError::Success.into()
}

/// Configure the mmap-based memory allocator.
///
/// MUST be called before `pk_init()` and before any allocations occur.
///
/// # Safety
///
/// `swap_file_path` must be either NULL or a valid null-terminated C string.
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
/// # Safety
///
/// All non-NULL pointers must be valid.
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

// ---------------------------------------------------------------------------
// Prepare
// ---------------------------------------------------------------------------

/// Compile a Noir circuit into prover and verifier handles.
///
/// No files are written and both handles live in memory. The caller must free
/// each handle exactly once via `pk_free_prover` / `pk_free_verifier`.
///
/// # Safety
///
/// - `circuit_path` must be a valid null-terminated C string.
/// - `out_prover` and `out_verifier` must be valid, non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn pk_prepare(
    circuit_path: *const c_char,
    out_prover: *mut *mut PKProver,
    out_verifier: *mut *mut PKVerifier,
) -> c_int {
    if out_prover.is_null() || out_verifier.is_null() {
        return PKError::InvalidInput.into();
    }

    catch_panic(PKError::CompilationError.into(), || {
        *out_prover = std::ptr::null_mut();
        *out_verifier = std::ptr::null_mut();

        let result = (|| -> Result<(*mut PKProver, *mut PKVerifier), PKError> {
            let circuit_path = c_str_to_str(circuit_path)?;

            let scheme = NoirCompiler::from_file(Path::new(&circuit_path), HashConfig::default())
                .map_err(|_| PKError::CompilationError)?;

            let prover = Prover::from_noir_proof_scheme(scheme.clone());
            let verifier = Verifier::from_noir_proof_scheme(scheme);

            let pk = Box::into_raw(Box::new(PKProver { prover }));
            let vk = Box::into_raw(Box::new(PKVerifier { verifier }));

            Ok((pk, vk))
        })();

        match result {
            Ok((pk, vk)) => {
                *out_prover = pk;
                *out_verifier = vk;
                PKError::Success.into()
            }
            Err(e) => e.into(),
        }
    })
}

// ---------------------------------------------------------------------------
// Load (from file path)
// ---------------------------------------------------------------------------

/// Load a prover scheme from a `.pkp` file.
///
/// # Safety
///
/// - `path` must be a valid null-terminated C string.
/// - `out` must be a valid, non-null pointer.
/// - The returned handle must be freed via `pk_free_prover`.
#[no_mangle]
pub unsafe extern "C" fn pk_load_prover(path: *const c_char, out: *mut *mut PKProver) -> c_int {
    if out.is_null() {
        return PKError::InvalidInput.into();
    }

    catch_panic(PKError::SchemeReadError.into(), || {
        *out = std::ptr::null_mut();

        let result = (|| -> Result<*mut PKProver, PKError> {
            let path = c_str_to_str(path)?;
            let prover: Prover =
                file::read(Path::new(&path)).map_err(|_| PKError::SchemeReadError)?;
            Ok(Box::into_raw(Box::new(PKProver { prover })))
        })();

        match result {
            Ok(handle) => {
                *out = handle;
                PKError::Success.into()
            }
            Err(e) => e.into(),
        }
    })
}

/// Load a verifier scheme from a `.pkv` file.
///
/// # Safety
///
/// - `path` must be a valid null-terminated C string.
/// - `out` must be a valid, non-null pointer.
/// - The returned handle must be freed via `pk_free_verifier`.
#[no_mangle]
pub unsafe extern "C" fn pk_load_verifier(path: *const c_char, out: *mut *mut PKVerifier) -> c_int {
    if out.is_null() {
        return PKError::InvalidInput.into();
    }

    catch_panic(PKError::SchemeReadError.into(), || {
        *out = std::ptr::null_mut();

        let result = (|| -> Result<*mut PKVerifier, PKError> {
            let path = c_str_to_str(path)?;
            let verifier: Verifier =
                file::read(Path::new(&path)).map_err(|_| PKError::SchemeReadError)?;
            Ok(Box::into_raw(Box::new(PKVerifier { verifier })))
        })();

        match result {
            Ok(handle) => {
                *out = handle;
                PKError::Success.into()
            }
            Err(e) => e.into(),
        }
    })
}

// ---------------------------------------------------------------------------
// Load (from bytes)
// ---------------------------------------------------------------------------

/// Load a prover scheme from bytes (same format as `.pkp` files).
///
/// # Safety
///
/// - `ptr` must point to `len` valid bytes.
/// - `out` must be a valid, non-null pointer.
/// - The returned handle must be freed via `pk_free_prover`.
#[no_mangle]
pub unsafe extern "C" fn pk_load_prover_bytes(
    ptr: *const u8,
    len: usize,
    out: *mut *mut PKProver,
) -> c_int {
    if out.is_null() || ptr.is_null() || len == 0 {
        return PKError::InvalidInput.into();
    }

    catch_panic(PKError::SchemeReadError.into(), || {
        *out = std::ptr::null_mut();

        let result = (|| -> Result<*mut PKProver, PKError> {
            let data = std::slice::from_raw_parts(ptr, len);
            let prover: Prover = file::deserialize(data).map_err(|_| PKError::SchemeReadError)?;
            Ok(Box::into_raw(Box::new(PKProver { prover })))
        })();

        match result {
            Ok(handle) => {
                *out = handle;
                PKError::Success.into()
            }
            Err(e) => e.into(),
        }
    })
}

/// Load a verifier scheme from bytes (same format as `.pkv` files).
///
/// # Safety
///
/// - `ptr` must point to `len` valid bytes.
/// - `out` must be a valid, non-null pointer.
/// - The returned handle must be freed via `pk_free_verifier`.
#[no_mangle]
pub unsafe extern "C" fn pk_load_verifier_bytes(
    ptr: *const u8,
    len: usize,
    out: *mut *mut PKVerifier,
) -> c_int {
    if out.is_null() || ptr.is_null() || len == 0 {
        return PKError::InvalidInput.into();
    }

    catch_panic(PKError::SchemeReadError.into(), || {
        *out = std::ptr::null_mut();

        let result = (|| -> Result<*mut PKVerifier, PKError> {
            let data = std::slice::from_raw_parts(ptr, len);
            let verifier: Verifier =
                file::deserialize(data).map_err(|_| PKError::SchemeReadError)?;
            Ok(Box::into_raw(Box::new(PKVerifier { verifier })))
        })();

        match result {
            Ok(handle) => {
                *out = handle;
                PKError::Success.into()
            }
            Err(e) => e.into(),
        }
    })
}

// ---------------------------------------------------------------------------
// Save (to file path)
// ---------------------------------------------------------------------------

/// Save a prover scheme to a `.pkp` file.
///
/// # Safety
///
/// - `prover` must be a valid handle from `pk_prepare` or `pk_load_prover`.
/// - `path` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pk_save_prover(prover: *const PKProver, path: *const c_char) -> c_int {
    if prover.is_null() {
        return PKError::InvalidInput.into();
    }

    catch_panic(PKError::FileWriteError.into(), || {
        let result = (|| -> Result<(), PKError> {
            let path = c_str_to_str(path)?;
            file::write(&(*prover).prover, Path::new(&path)).map_err(|_| PKError::FileWriteError)
        })();

        match result {
            Ok(()) => PKError::Success.into(),
            Err(e) => e.into(),
        }
    })
}

/// Save a verifier scheme to a `.pkv` file.
///
/// # Safety
///
/// - `verifier` must be a valid handle from `pk_prepare` or `pk_load_verifier`.
/// - `path` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn pk_save_verifier(
    verifier: *const PKVerifier,
    path: *const c_char,
) -> c_int {
    if verifier.is_null() {
        return PKError::InvalidInput.into();
    }

    catch_panic(PKError::FileWriteError.into(), || {
        let result = (|| -> Result<(), PKError> {
            let path = c_str_to_str(path)?;
            file::write(&(*verifier).verifier, Path::new(&path))
                .map_err(|_| PKError::FileWriteError)
        })();

        match result {
            Ok(()) => PKError::Success.into(),
            Err(e) => e.into(),
        }
    })
}

// ---------------------------------------------------------------------------
// Serialize (to bytes)
// ---------------------------------------------------------------------------

/// Serialize a prover scheme to bytes (same format as `.pkp` files).
///
/// # Safety
///
/// - `prover` must be a valid handle.
/// - `out_buf` must be a valid, non-null pointer.
/// - The returned buffer must be freed via `pk_free_buf`.
#[no_mangle]
pub unsafe extern "C" fn pk_serialize_prover(
    prover: *const PKProver,
    out_buf: *mut PKBuf,
) -> c_int {
    if prover.is_null() || out_buf.is_null() {
        return PKError::InvalidInput.into();
    }

    catch_panic(PKError::SerializationError.into(), || {
        let out_buf = &mut *out_buf;
        *out_buf = PKBuf::empty();

        match file::serialize(&(*prover).prover) {
            Ok(bytes) => {
                *out_buf = PKBuf::from_vec(bytes);
                PKError::Success.into()
            }
            Err(_) => PKError::SerializationError.into(),
        }
    })
}

/// Serialize a verifier scheme to bytes (same format as `.pkv` files).
///
/// # Safety
///
/// - `verifier` must be a valid handle.
/// - `out_buf` must be a valid, non-null pointer.
/// - The returned buffer must be freed via `pk_free_buf`.
#[no_mangle]
pub unsafe extern "C" fn pk_serialize_verifier(
    verifier: *const PKVerifier,
    out_buf: *mut PKBuf,
) -> c_int {
    if verifier.is_null() || out_buf.is_null() {
        return PKError::InvalidInput.into();
    }

    catch_panic(PKError::SerializationError.into(), || {
        let out_buf = &mut *out_buf;
        *out_buf = PKBuf::empty();

        match file::serialize(&(*verifier).verifier) {
            Ok(bytes) => {
                *out_buf = PKBuf::from_vec(bytes);
                PKError::Success.into()
            }
            Err(_) => PKError::SerializationError.into(),
        }
    })
}

// ---------------------------------------------------------------------------
// Prove
// ---------------------------------------------------------------------------

/// Prove using a prover handle and a TOML input file.
///
/// Returns proof bytes in `out_proof`. The caller must free the buffer via
/// `pk_free_buf`.
///
/// # Safety
///
/// - `prover` must be a valid handle.
/// - `toml_path` must be a valid null-terminated C string.
/// - `out_proof` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn pk_prove_toml(
    prover: *const PKProver,
    toml_path: *const c_char,
    out_proof: *mut PKBuf,
) -> c_int {
    if prover.is_null() || out_proof.is_null() {
        return PKError::InvalidInput.into();
    }

    catch_panic(PKError::ProofError.into(), || {
        let out_proof = &mut *out_proof;
        *out_proof = PKBuf::empty();

        let result = (|| -> Result<Vec<u8>, PKError> {
            let toml_path = c_str_to_str(toml_path)?;

            let fresh_prover = (*prover).prover.clone();
            let proof = fresh_prover
                .prove_with_toml(Path::new(&toml_path))
                .map_err(|_| PKError::ProofError)?;

            postcard::to_allocvec(&proof).map_err(|_| PKError::SerializationError)
        })();

        match result {
            Ok(bytes) => {
                *out_proof = PKBuf::from_vec(bytes);
                PKError::Success.into()
            }
            Err(e) => e.into(),
        }
    })
}

/// Prove using a prover handle and a JSON string of inputs.
///
/// The JSON must match the circuit's ABI. Example:
/// `{"x": "5", "y": "10"}` for `fn main(x: Field, y: Field)`.
///
/// Returns proof bytes in `out_proof`. The caller must free the buffer via
/// `pk_free_buf`.
///
/// # Safety
///
/// - `prover` must be a valid handle.
/// - `inputs_json` must be a valid null-terminated UTF-8 C string.
/// - `out_proof` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn pk_prove_json(
    prover: *const PKProver,
    inputs_json: *const c_char,
    out_proof: *mut PKBuf,
) -> c_int {
    if prover.is_null() || out_proof.is_null() {
        return PKError::InvalidInput.into();
    }

    catch_panic(PKError::ProofError.into(), || {
        let out_proof = &mut *out_proof;
        *out_proof = PKBuf::empty();

        let result = (|| -> Result<Vec<u8>, PKError> {
            let json_str = c_str_to_str(inputs_json)?;

            // Get ABI from the prover to parse inputs
            let abi = match &(*prover).prover {
                Prover::Noir(p) => p.witness_generator.abi(),
                Prover::Mavros(_) => return Err(PKError::InvalidInput),
            };

            let format = Format::from_ext("json").ok_or(PKError::InvalidInput)?;
            let input_map = format
                .parse(&json_str, abi)
                .map_err(|_| PKError::WitnessReadError)?;

            let fresh_prover = (*prover).prover.clone();
            let proof = fresh_prover
                .prove(input_map)
                .map_err(|_| PKError::ProofError)?;

            postcard::to_allocvec(&proof).map_err(|_| PKError::SerializationError)
        })();

        match result {
            Ok(bytes) => {
                *out_proof = PKBuf::from_vec(bytes);
                PKError::Success.into()
            }
            Err(e) => e.into(),
        }
    })
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/// Verify a proof using a verifier handle.
///
/// Returns `PKError::Success` (0) if valid, `PKError::ProofError` (4) if
/// invalid.
///
/// # Safety
///
/// - `verifier` must be a valid handle.
/// - `proof_ptr` must point to `proof_len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn pk_verify(
    verifier: *const PKVerifier,
    proof_ptr: *const u8,
    proof_len: usize,
) -> c_int {
    if verifier.is_null() || proof_ptr.is_null() || proof_len == 0 {
        return PKError::InvalidInput.into();
    }

    catch_panic(PKError::ProofError.into(), || {
        let result = (|| -> Result<bool, PKError> {
            let proof_bytes = std::slice::from_raw_parts(proof_ptr, proof_len);
            let proof: NoirProof =
                postcard::from_bytes(proof_bytes).map_err(|_| PKError::SerializationError)?;

            let mut fresh_verifier = (*verifier).verifier.clone();
            match fresh_verifier.verify(&proof) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        })();

        match result {
            Ok(true) => PKError::Success.into(),
            Ok(false) => PKError::ProofError.into(),
            Err(e) => e.into(),
        }
    })
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

/// Free a prover handle.
///
/// # Safety
///
/// `prover` must have been created by `pk_prepare` or `pk_load_prover`
/// and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn pk_free_prover(prover: *mut PKProver) {
    if !prover.is_null() {
        drop(Box::from_raw(prover));
    }
}

/// Free a verifier handle.
///
/// # Safety
///
/// `verifier` must have been created by `pk_prepare` or `pk_load_verifier`
/// and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn pk_free_verifier(verifier: *mut PKVerifier) {
    if !verifier.is_null() {
        drop(Box::from_raw(verifier));
    }
}

/// Free a buffer allocated by ProveKit FFI functions.
///
/// # Safety
///
/// The buffer must have been allocated by a ProveKit FFI function and must
/// not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn pk_free_buf(buf: PKBuf) {
    if !buf.ptr.is_null() && buf.cap > 0 {
        drop(Vec::from_raw_parts(buf.ptr, buf.len, buf.cap));
    }
}
