//! Integration tests for provekit-ffi.
//!
//! Exercises the C FFI functions directly from Rust, covering the full
//! lifecycle: init, prepare, prove, verify, serialize/deserialize,
//! save/load, error handling, and cleanup.
//!
//! Requires the basic-2 circuit artifact to exist at
//! `noir-examples/basic-2/target/basic.json`. Compile it first if needed:
//! `cargo run -p provekit -- compile noir-examples/basic-2`
//!
//! **Note on debug builds:** Tests that call `pk_verify` on a valid proof are
//! `#[ignore]`d under `debug_assertions` because `WhirR1CSProof.pattern` is
//! `#[cfg(debug_assertions)] #[serde(skip)]` — it gets populated by the prover
//! but lost during the serialize/deserialize round-trip that the FFI always
//! performs. The WHIR transcript then panics on the empty pattern. Run these
//! with `--release` (the real-world FFI build profile).

use std::ffi::{CStr, CString};
use std::os::raw::c_int;
use std::ptr;
use std::sync::Once;

use provekit_ffi::{
    pk_free_buf, pk_free_prover, pk_free_verifier, pk_get_last_error, pk_init, pk_load_prover,
    pk_load_prover_bytes, pk_load_verifier, pk_load_verifier_bytes, pk_prepare, pk_prove_json,
    pk_prove_toml, pk_save_prover, pk_save_verifier, pk_serialize_prover, pk_serialize_verifier,
    pk_verify, PKBuf, PKProver, PKStatus, PKVerifier,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static INIT: Once = Once::new();

fn init() {
    INIT.call_once(|| {
        assert_eq!(pk_init(), PKStatus::Success as c_int);
    });
}

/// Path to the compiled basic-2 circuit artifact.
fn circuit_path() -> CString {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest}/../../noir-examples/basic-2/target/basic.json");
    assert!(
        std::path::Path::new(&path).exists(),
        "circuit artifact not found at {path}; compile basic-2 first"
    );
    CString::new(path).unwrap()
}

/// Path to basic-2 Prover.toml input file.
fn toml_path() -> CString {
    let manifest = env!("CARGO_MANIFEST_DIR");
    CString::new(format!(
        "{manifest}/../../noir-examples/basic-2/Prover.toml"
    ))
    .unwrap()
}

/// Run `pk_prepare` and return (prover, verifier).
unsafe fn prepare_handles() -> (*mut PKProver, *mut PKVerifier) {
    let path = circuit_path();
    let mut prover: *mut PKProver = ptr::null_mut();
    let mut verifier: *mut PKVerifier = ptr::null_mut();
    let status = pk_prepare(path.as_ptr(), &mut prover, &mut verifier);
    assert_eq!(status, PKStatus::Success as c_int, "pk_prepare failed");
    assert!(!prover.is_null());
    assert!(!verifier.is_null());
    (prover, verifier)
}

/// Read the thread-local last-error message (clears it).
unsafe fn last_error() -> String {
    let mut buf = PKBuf::empty();
    let status = pk_get_last_error(&mut buf);
    assert_eq!(status, PKStatus::Success as c_int);
    let msg = if buf.len > 0 && !buf.ptr.is_null() {
        let bytes = std::slice::from_raw_parts(buf.ptr, buf.len);
        String::from_utf8_lossy(bytes).to_string()
    } else {
        String::new()
    };
    pk_free_buf(buf);
    msg
}

/// Prove with the basic-2 Prover.toml and return proof bytes.
unsafe fn prove_toml(prover: *const PKProver) -> Vec<u8> {
    let toml = toml_path();
    let mut proof_buf = PKBuf::empty();
    let status = pk_prove_toml(prover, toml.as_ptr(), &mut proof_buf);
    assert_eq!(status, PKStatus::Success as c_int, "pk_prove_toml failed");
    assert!(!proof_buf.ptr.is_null());
    assert!(proof_buf.len > 0);
    let bytes = std::slice::from_raw_parts(proof_buf.ptr, proof_buf.len).to_vec();
    pk_free_buf(proof_buf);
    bytes
}

// =========================================================================
// 1. Error Reporting (`pk_get_last_error`)
// =========================================================================

#[test]
fn error_reporting_failed_call_sets_message() {
    init();
    unsafe {
        let bad = CString::new("/nonexistent/circuit.json").unwrap();
        let mut p: *mut PKProver = ptr::null_mut();
        let mut v: *mut PKVerifier = ptr::null_mut();
        let status = pk_prepare(bad.as_ptr(), &mut p, &mut v);
        assert_ne!(status, PKStatus::Success as c_int);

        let err = last_error();
        assert!(!err.is_empty(), "expected non-empty error message");
    }
}

#[test]
fn error_reporting_clears_on_read() {
    init();
    unsafe {
        // Trigger an error.
        let bad = CString::new("/nonexistent/file.pkp").unwrap();
        let mut out: *mut PKProver = ptr::null_mut();
        pk_load_prover(bad.as_ptr(), &mut out);

        let first = last_error();
        assert!(!first.is_empty());

        // Second read should be empty.
        let second = last_error();
        assert!(second.is_empty(), "error should clear after read");
    }
}

#[test]
fn error_reporting_null_c_string() {
    init();
    unsafe {
        let mut out: *mut PKProver = ptr::null_mut();
        let status = pk_load_prover(ptr::null(), &mut out);
        assert_ne!(status, PKStatus::Success as c_int);

        let err = last_error();
        assert!(err.contains("null"), "expected null-pointer error, got: {err}");
    }
}

#[test]
fn error_reporting_invalid_utf8() {
    init();
    unsafe {
        // 0xFF 0xFE is invalid UTF-8; 0x00 is the null terminator.
        let invalid: &[u8] = &[0xFF, 0xFE, 0x00];
        let c_str = CStr::from_bytes_with_nul(invalid).unwrap();

        let mut out: *mut PKProver = ptr::null_mut();
        let status = pk_load_prover(c_str.as_ptr(), &mut out);
        assert_eq!(status, PKStatus::Utf8Error as c_int);

        let err = last_error();
        assert!(
            err.to_lowercase().contains("utf-8") || err.to_lowercase().contains("utf8"),
            "expected UTF-8 error, got: {err}"
        );
    }
}

// =========================================================================
// 2. Prepare Flow (`pk_prepare`)
// =========================================================================

#[test]
fn prepare_success_returns_non_null_handles() {
    init();
    unsafe {
        let (prover, verifier) = prepare_handles();
        pk_free_prover(prover);
        pk_free_verifier(verifier);
    }
}

#[test]
fn prepare_null_circuit_path() {
    init();
    unsafe {
        let mut p: *mut PKProver = ptr::null_mut();
        let mut v: *mut PKVerifier = ptr::null_mut();
        let status = pk_prepare(ptr::null(), &mut p, &mut v);
        assert_ne!(status, PKStatus::Success as c_int);
    }
}

#[test]
fn prepare_null_output_pointers() {
    init();
    unsafe {
        let path = circuit_path();
        let status = pk_prepare(path.as_ptr(), ptr::null_mut(), ptr::null_mut());
        assert_eq!(status, PKStatus::InvalidInput as c_int);
    }
}

// =========================================================================
// 3. Prove + Verify Round-Trip
// =========================================================================

#[test]
#[cfg_attr(debug_assertions, ignore = "WHIR pattern lost across FFI serialize round-trip")]
fn prove_verify_toml_round_trip() {
    init();
    unsafe {
        let (prover, verifier) = prepare_handles();

        let proof = prove_toml(prover);

        let status = pk_verify(verifier, proof.as_ptr(), proof.len());
        assert_eq!(status, PKStatus::Success as c_int, "verification failed");

        pk_free_prover(prover);
        pk_free_verifier(verifier);
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "WHIR pattern lost across FFI serialize round-trip")]
fn verify_corrupted_proof_fails() {
    init();
    unsafe {
        let (prover, verifier) = prepare_handles();

        let mut proof = prove_toml(prover);

        // Corrupt bytes in the middle of the proof.
        let mid = proof.len() / 2;
        let end = mid.saturating_add(16).min(proof.len());
        for b in &mut proof[mid..end] {
            *b ^= 0xFF;
        }

        let status = pk_verify(verifier, proof.as_ptr(), proof.len());
        assert_ne!(
            status,
            PKStatus::Success as c_int,
            "corrupted proof should not verify"
        );

        pk_free_prover(prover);
        pk_free_verifier(verifier);
    }
}

#[test]
fn verify_null_verifier() {
    init();
    unsafe {
        let dummy = [0u8; 64];
        let status = pk_verify(ptr::null(), dummy.as_ptr(), dummy.len());
        assert_eq!(status, PKStatus::InvalidInput as c_int);
    }
}

#[test]
fn verify_null_proof_ptr() {
    init();
    unsafe {
        let (prover, verifier) = prepare_handles();

        let status = pk_verify(verifier, ptr::null(), 0);
        assert_eq!(status, PKStatus::InvalidInput as c_int);

        pk_free_prover(prover);
        pk_free_verifier(verifier);
    }
}

// =========================================================================
// 4. pk_prove_json
// =========================================================================

#[test]
#[cfg_attr(debug_assertions, ignore = "WHIR pattern lost across FFI serialize round-trip")]
fn prove_verify_json_round_trip() {
    init();
    unsafe {
        let (prover, verifier) = prepare_handles();

        // basic-2: fn main(a, b, c, d) { assert(a*b + c + d == 10); }
        let json = CString::new(r#"{"a":"1","b":"2","c":"3","d":"5"}"#).unwrap();
        let mut proof_buf = PKBuf::empty();
        let status = pk_prove_json(prover, json.as_ptr(), &mut proof_buf);
        assert_eq!(status, PKStatus::Success as c_int, "pk_prove_json failed");
        assert!(proof_buf.len > 0);

        let proof = std::slice::from_raw_parts(proof_buf.ptr, proof_buf.len).to_vec();
        pk_free_buf(proof_buf);

        let status = pk_verify(verifier, proof.as_ptr(), proof.len());
        assert_eq!(
            status,
            PKStatus::Success as c_int,
            "json proof verification failed"
        );

        pk_free_prover(prover);
        pk_free_verifier(verifier);
    }
}

#[test]
fn prove_json_wrong_field_names() {
    init();
    unsafe {
        let (prover, verifier) = prepare_handles();

        let bad = CString::new(r#"{"x":"1","y":"2"}"#).unwrap();
        let mut proof_buf = PKBuf::empty();
        let status = pk_prove_json(prover, bad.as_ptr(), &mut proof_buf);
        assert_ne!(
            status,
            PKStatus::Success as c_int,
            "wrong field names should fail"
        );

        pk_free_prover(prover);
        pk_free_verifier(verifier);
    }
}

#[test]
fn prove_json_null_inputs() {
    init();
    unsafe {
        let (prover, verifier) = prepare_handles();

        let mut proof_buf = PKBuf::empty();
        let status = pk_prove_json(prover, ptr::null(), &mut proof_buf);
        assert_ne!(status, PKStatus::Success as c_int);

        pk_free_prover(prover);
        pk_free_verifier(verifier);
    }
}

// =========================================================================
// 5. Serialize / Deserialize Round-Trip
// =========================================================================

#[test]
#[cfg_attr(debug_assertions, ignore = "WHIR pattern lost across FFI serialize round-trip")]
fn serialize_deserialize_prover_round_trip() {
    init();
    unsafe {
        let (prover, verifier) = prepare_handles();

        // Serialize the prover to bytes.
        let mut buf = PKBuf::empty();
        let status = pk_serialize_prover(prover, &mut buf);
        assert_eq!(status, PKStatus::Success as c_int, "serialize prover failed");
        assert!(buf.len > 0);

        // Reload from bytes.
        let mut loaded: *mut PKProver = ptr::null_mut();
        let status = pk_load_prover_bytes(buf.ptr, buf.len, &mut loaded);
        assert_eq!(
            status,
            PKStatus::Success as c_int,
            "load prover from bytes failed"
        );
        assert!(!loaded.is_null());

        // Prove with the reloaded prover, verify with original verifier.
        let proof = prove_toml(loaded);
        let status = pk_verify(verifier, proof.as_ptr(), proof.len());
        assert_eq!(
            status,
            PKStatus::Success as c_int,
            "proof from deserialized prover should verify"
        );

        pk_free_buf(buf);
        pk_free_prover(prover);
        pk_free_prover(loaded);
        pk_free_verifier(verifier);
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "WHIR pattern lost across FFI serialize round-trip")]
fn serialize_deserialize_verifier_round_trip() {
    init();
    unsafe {
        let (prover, verifier) = prepare_handles();

        // Serialize the verifier to bytes.
        let mut buf = PKBuf::empty();
        let status = pk_serialize_verifier(verifier, &mut buf);
        assert_eq!(
            status,
            PKStatus::Success as c_int,
            "serialize verifier failed"
        );
        assert!(buf.len > 0);

        // Reload from bytes.
        let mut loaded: *mut PKVerifier = ptr::null_mut();
        let status = pk_load_verifier_bytes(buf.ptr, buf.len, &mut loaded);
        assert_eq!(
            status,
            PKStatus::Success as c_int,
            "load verifier from bytes failed"
        );
        assert!(!loaded.is_null());

        // Prove with original prover, verify with reloaded verifier.
        let proof = prove_toml(prover);
        let status = pk_verify(loaded, proof.as_ptr(), proof.len());
        assert_eq!(
            status,
            PKStatus::Success as c_int,
            "deserialized verifier should accept valid proof"
        );

        pk_free_buf(buf);
        pk_free_prover(prover);
        pk_free_verifier(verifier);
        pk_free_verifier(loaded);
    }
}

// =========================================================================
// 6. Save / Load File Round-Trip
// =========================================================================

#[test]
#[cfg_attr(debug_assertions, ignore = "WHIR pattern lost across FFI serialize round-trip")]
fn save_load_prover_file_round_trip() {
    init();
    unsafe {
        let (prover, verifier) = prepare_handles();

        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("test.pkp");
        let path_c = CString::new(path.to_str().unwrap()).unwrap();

        // Save.
        let status = pk_save_prover(prover, path_c.as_ptr());
        assert_eq!(status, PKStatus::Success as c_int, "save prover failed");
        assert!(path.exists());

        // Load.
        let mut loaded: *mut PKProver = ptr::null_mut();
        let status = pk_load_prover(path_c.as_ptr(), &mut loaded);
        assert_eq!(status, PKStatus::Success as c_int, "load prover failed");
        assert!(!loaded.is_null());

        // Prove and verify.
        let proof = prove_toml(loaded);
        let status = pk_verify(verifier, proof.as_ptr(), proof.len());
        assert_eq!(
            status,
            PKStatus::Success as c_int,
            "file-loaded prover should produce valid proofs"
        );

        pk_free_prover(prover);
        pk_free_prover(loaded);
        pk_free_verifier(verifier);
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "WHIR pattern lost across FFI serialize round-trip")]
fn save_load_verifier_file_round_trip() {
    init();
    unsafe {
        let (prover, verifier) = prepare_handles();

        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("test.pkv");
        let path_c = CString::new(path.to_str().unwrap()).unwrap();

        // Save.
        let status = pk_save_verifier(verifier, path_c.as_ptr());
        assert_eq!(status, PKStatus::Success as c_int, "save verifier failed");
        assert!(path.exists());

        // Load.
        let mut loaded: *mut PKVerifier = ptr::null_mut();
        let status = pk_load_verifier(path_c.as_ptr(), &mut loaded);
        assert_eq!(status, PKStatus::Success as c_int, "load verifier failed");
        assert!(!loaded.is_null());

        // Prove and verify.
        let proof = prove_toml(prover);
        let status = pk_verify(loaded, proof.as_ptr(), proof.len());
        assert_eq!(
            status,
            PKStatus::Success as c_int,
            "file-loaded verifier should accept valid proofs"
        );

        pk_free_prover(prover);
        pk_free_verifier(verifier);
        pk_free_verifier(loaded);
    }
}

// =========================================================================
// 7. PKStatus Codes
// =========================================================================

#[test]
fn status_invalid_input_on_null_args() {
    init();
    unsafe {
        // pk_verify — null verifier.
        assert_eq!(
            pk_verify(ptr::null(), ptr::null(), 0),
            PKStatus::InvalidInput as c_int
        );

        // pk_prove_toml — null prover.
        let toml = toml_path();
        let mut buf = PKBuf::empty();
        assert_eq!(
            pk_prove_toml(ptr::null(), toml.as_ptr(), &mut buf),
            PKStatus::InvalidInput as c_int
        );

        // pk_prove_json — null prover.
        let json = CString::new("{}").unwrap();
        let mut buf = PKBuf::empty();
        assert_eq!(
            pk_prove_json(ptr::null(), json.as_ptr(), &mut buf),
            PKStatus::InvalidInput as c_int
        );

        // pk_serialize_prover — null handle.
        let mut buf = PKBuf::empty();
        assert_eq!(
            pk_serialize_prover(ptr::null(), &mut buf),
            PKStatus::InvalidInput as c_int
        );

        // pk_serialize_verifier — null handle.
        let mut buf = PKBuf::empty();
        assert_eq!(
            pk_serialize_verifier(ptr::null(), &mut buf),
            PKStatus::InvalidInput as c_int
        );

        // pk_save_prover — null handle.
        let path = CString::new("/tmp/test.pkp").unwrap();
        assert_eq!(
            pk_save_prover(ptr::null(), path.as_ptr()),
            PKStatus::InvalidInput as c_int
        );

        // pk_save_verifier — null handle.
        let path = CString::new("/tmp/test.pkv").unwrap();
        assert_eq!(
            pk_save_verifier(ptr::null(), path.as_ptr()),
            PKStatus::InvalidInput as c_int
        );

        // pk_get_last_error — null output.
        assert_eq!(
            pk_get_last_error(ptr::null_mut()),
            PKStatus::InvalidInput as c_int
        );
    }
}

#[test]
fn status_scheme_read_error_bad_prover_file() {
    init();
    unsafe {
        let bad = CString::new("/nonexistent/file.pkp").unwrap();
        let mut out: *mut PKProver = ptr::null_mut();
        assert_eq!(
            pk_load_prover(bad.as_ptr(), &mut out),
            PKStatus::SchemeReadError as c_int
        );
        assert!(out.is_null());
    }
}

#[test]
fn status_scheme_read_error_bad_verifier_file() {
    init();
    unsafe {
        let bad = CString::new("/nonexistent/file.pkv").unwrap();
        let mut out: *mut PKVerifier = ptr::null_mut();
        assert_eq!(
            pk_load_verifier(bad.as_ptr(), &mut out),
            PKStatus::SchemeReadError as c_int
        );
        assert!(out.is_null());
    }
}

#[test]
fn status_invalid_input_zero_length_bytes() {
    init();
    unsafe {
        let mut out: *mut PKProver = ptr::null_mut();
        assert_eq!(
            pk_load_prover_bytes(ptr::null(), 0, &mut out),
            PKStatus::InvalidInput as c_int
        );

        let mut out: *mut PKVerifier = ptr::null_mut();
        assert_eq!(
            pk_load_verifier_bytes(ptr::null(), 0, &mut out),
            PKStatus::InvalidInput as c_int
        );
    }
}

// =========================================================================
// 8. Cleanup
// =========================================================================

#[test]
fn free_null_prover_no_crash() {
    unsafe {
        pk_free_prover(ptr::null_mut());
    }
}

#[test]
fn free_null_verifier_no_crash() {
    unsafe {
        pk_free_verifier(ptr::null_mut());
    }
}

#[test]
fn free_empty_buf_no_crash() {
    unsafe {
        pk_free_buf(PKBuf::empty());
    }
}

#[test]
fn free_prover_after_use() {
    init();
    unsafe {
        let (prover, verifier) = prepare_handles();
        let _proof = prove_toml(prover);
        // Freeing after proving should not crash.
        pk_free_prover(prover);
        pk_free_verifier(verifier);
    }
}
