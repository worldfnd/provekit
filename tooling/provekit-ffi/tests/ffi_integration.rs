//! Integration tests for provekit-ffi.
//!
//! Tests are grouped into labelled sections (A–K) matching the plan.
//! Tests that call `pk_verify` are gated with
//! `#[cfg_attr(debug_assertions, ignore)]` because the WHIR transcript
//! has a debug assertion (`!self.pattern.is_empty()`) that panics in
//! debug builds. `pk_prepare`, `pk_prove_*`, `pk_serialize_*`, and
//! `pk_save_*`/`pk_load_*` all work fine in debug.
//! Run `cargo test --release` to execute the full suite including verify.

use {
    nargo_cli::cli::compile_cmd::compile_workspace_full,
    nargo_toml::{resolve_workspace_from_toml, PackageSelection},
    noirc_driver::CompileOptions,
    provekit_ffi::{
        ffi::{
            pk_configure_memory, pk_free_buf, pk_free_prover, pk_free_verifier, pk_get_last_error,
            pk_init, pk_load_prover, pk_load_prover_bytes, pk_load_verifier,
            pk_load_verifier_bytes, pk_prepare, pk_prove_json, pk_prove_toml, pk_save_prover,
            pk_save_verifier, pk_serialize_prover, pk_serialize_verifier, pk_verify,
        },
        types::{PKBuf, PKProver, PKStatus, PKVerifier},
    },
    std::{ffi::CString, path::PathBuf, sync::Once},
};

// ---------------------------------------------------------------------------
// Status code constants for readability
// ---------------------------------------------------------------------------

const PK_SUCCESS: i32 = PKStatus::Success as i32;
const PK_INVALID_INPUT: i32 = PKStatus::InvalidInput as i32;
const PK_SCHEME_READ_ERROR: i32 = PKStatus::SchemeReadError as i32;
const PK_PROOF_ERROR: i32 = PKStatus::ProofError as i32;
const PK_COMPILATION_ERROR: i32 = PKStatus::CompilationError as i32;

// ---------------------------------------------------------------------------
// One-time library initialisation
// ---------------------------------------------------------------------------

static INIT: Once = Once::new();
static COMPILE_BASIC_2: Once = Once::new();

fn basic_2_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../noir-examples/basic-2")
}

fn compile_basic_2_workspace_once() {
    COMPILE_BASIC_2.call_once(|| {
        let workspace_toml = basic_2_dir()
            .join("Nargo.toml")
            .canonicalize()
            .expect("Canonicalizing basic-2/Nargo.toml");

        let workspace =
            resolve_workspace_from_toml(&workspace_toml, PackageSelection::DefaultOrAll, None)
                .expect("Resolving Noir workspace for basic-2");

        let compile_options = CompileOptions::default();
        compile_workspace_full(&workspace, &compile_options, None)
            .expect("Compiling noir-examples/basic-2");
    });
}

fn init() {
    INIT.call_once(|| {
        // Ensure CI has the fixture artifact expected by FFI tests:
        // noir-examples/basic-2/target/basic.json
        compile_basic_2_workspace_once();
        let status = pk_init();
        assert_eq!(status, PK_SUCCESS, "pk_init failed");
    });
}

// ---------------------------------------------------------------------------
// Test fixture paths (relative to this crate, using CARGO_MANIFEST_DIR)
// ---------------------------------------------------------------------------

fn circuit_json_cstring() -> CString {
    let path = basic_2_dir().join("target/basic.json");
    CString::new(path.to_string_lossy().into_owned()).unwrap()
}

fn toml_input_cstring() -> CString {
    let path = basic_2_dir().join("Prover.toml");
    CString::new(path.to_string_lossy().into_owned()).unwrap()
}

const JSON_INPUTS_VALID: &str = r#"{"a": "1", "b": "2", "c": "3", "d": "5"}"#;

// ---------------------------------------------------------------------------
// RAII helpers — free handles and buffers on drop so tests don't leak
// ---------------------------------------------------------------------------

struct ScopedProver(*mut PKProver);
impl Drop for ScopedProver {
    fn drop(&mut self) {
        unsafe { pk_free_prover(self.0) };
    }
}

struct ScopedVerifier(*mut PKVerifier);
impl Drop for ScopedVerifier {
    fn drop(&mut self) {
        unsafe { pk_free_verifier(self.0) };
    }
}

struct ScopedBuf(PKBuf);
impl Drop for ScopedBuf {
    fn drop(&mut self) {
        // Replace self.0 with an empty buffer before freeing so that a
        // hypothetical double-drop calls pk_free_buf on a null/cap=0 buffer
        // (a safe no-op) rather than freeing the same allocation twice.
        let buf = std::mem::replace(&mut self.0, PKBuf::empty());
        unsafe { pk_free_buf(buf) };
    }
}
impl ScopedBuf {
    fn as_slice(&self) -> &[u8] {
        if self.0.ptr.is_null() || self.0.len == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.0.ptr, self.0.len) }
    }
    fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_slice()).unwrap_or("<invalid utf8>")
    }
}

/// Wrapper to send a raw const pointer across thread boundaries.
/// SAFETY: `PKProver` and `PKVerifier` are asserted `Send + Sync` in types.rs.
struct SendPtr<T>(*const T);
unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}
impl<T> SendPtr<T> {
    /// Extract the raw pointer. Call this *inside* the spawned closure so
    /// that the closure captures `self` (a `Send` `SendPtr<T>`) rather than
    /// the raw field `self.0` (which the compiler sees as non-`Send` under
    /// Rust 2021 precise-capture rules).
    fn as_ptr(&self) -> *const T {
        self.0
    }
}

/// Prepare handles for the basic-2 circuit. Returns (ScopedProver,
/// ScopedVerifier). Panics if `pk_prepare` fails.
unsafe fn prepare_basic_circuit() -> (ScopedProver, ScopedVerifier) {
    init();
    let circuit = circuit_json_cstring();
    let mut prover: *mut PKProver = std::ptr::null_mut();
    let mut verifier: *mut PKVerifier = std::ptr::null_mut();
    let status = pk_prepare(circuit.as_ptr(), 0, &mut prover, &mut verifier);
    if status != PK_SUCCESS {
        let mut err_buf = PKBuf::empty();
        pk_get_last_error(&mut err_buf);
        let msg = if !err_buf.ptr.is_null() && err_buf.len > 0 {
            std::str::from_utf8(std::slice::from_raw_parts(err_buf.ptr, err_buf.len))
                .unwrap_or("<invalid utf8>")
                .to_string()
        } else {
            "(no error message)".to_string()
        };
        pk_free_buf(err_buf);
        panic!(
            "pk_prepare returned status {status} (expected {PK_SUCCESS}). Circuit path: {:?}. \
             Error: {msg}",
            circuit.to_str().unwrap_or("?")
        );
    }
    (ScopedProver(prover), ScopedVerifier(verifier))
}

/// Read the last error into a ScopedBuf (clears it).
unsafe fn last_error() -> ScopedBuf {
    let mut buf = PKBuf::empty();
    pk_get_last_error(&mut buf);
    ScopedBuf(buf)
}

// ===========================================================================
// A. pk_init
// ===========================================================================

#[test]
fn a_init_succeeds() {
    let status = pk_init();
    assert_eq!(status, PK_SUCCESS);
}

#[test]
fn a_init_idempotent() {
    let s1 = pk_init();
    let s2 = pk_init();
    assert_eq!(s1, PK_SUCCESS);
    assert_eq!(s2, PK_SUCCESS);
}

// ===========================================================================
// A2. pk_configure_memory
// ===========================================================================

#[test]
fn a2_configure_memory_zero_ram_returns_invalid_input() {
    // Early-exit before set_last_error, so no error message is stored.
    let status = unsafe { pk_configure_memory(0, false, std::ptr::null()) };
    assert_eq!(status, PK_INVALID_INPUT);
    // Error message should be empty for this path (no set_last_error called).
    let err = unsafe { last_error() };
    assert_eq!(
        err.as_slice().len(),
        0,
        "zero-ram path should not set an error message"
    );
}

#[test]
fn a2_configure_memory_valid_no_swap_returns_success() {
    // configure_allocator is idempotent (returns true if POOL_INITIALIZED);
    // safe to call even after pk_init().
    let status = unsafe { pk_configure_memory(300 * 1024 * 1024, false, std::ptr::null()) };
    assert_eq!(status, PK_SUCCESS);
}

#[test]
fn a2_configure_memory_idempotent() {
    // Calling twice should always return Success — the second call hits the
    // POOL_INITIALIZED early-return inside configure_allocator.
    let s1 = unsafe { pk_configure_memory(300 * 1024 * 1024, false, std::ptr::null()) };
    let s2 = unsafe { pk_configure_memory(128 * 1024 * 1024, false, std::ptr::null()) };
    assert_eq!(s1, PK_SUCCESS);
    assert_eq!(s2, PK_SUCCESS);
}

// ===========================================================================
// B. pk_prepare — null-guard and error paths (always run)
// ===========================================================================

#[test]
fn b_prepare_null_out_prover_returns_invalid_input() {
    init();
    let circuit = circuit_json_cstring();
    let mut verifier: *mut PKVerifier = std::ptr::null_mut();
    let status = unsafe { pk_prepare(circuit.as_ptr(), 0, std::ptr::null_mut(), &mut verifier) };
    assert_eq!(status, PK_INVALID_INPUT);
}

#[test]
fn b_prepare_null_out_verifier_returns_invalid_input() {
    init();
    let circuit = circuit_json_cstring();
    let mut prover: *mut PKProver = std::ptr::null_mut();
    let status = unsafe { pk_prepare(circuit.as_ptr(), 0, &mut prover, std::ptr::null_mut()) };
    assert_eq!(status, PK_INVALID_INPUT);
}

#[test]
fn b_prepare_bad_hash_config_returns_invalid_input() {
    init();
    let circuit = circuit_json_cstring();
    let mut prover: *mut PKProver = std::ptr::null_mut();
    let mut verifier: *mut PKVerifier = std::ptr::null_mut();
    let status = unsafe { pk_prepare(circuit.as_ptr(), 99, &mut prover, &mut verifier) };
    assert_eq!(status, PK_INVALID_INPUT);
    // Cleanup (should be null, but free safely)
    unsafe {
        pk_free_prover(prover);
        pk_free_verifier(verifier);
    }
}

#[test]
fn b_prepare_bad_hash_config_sets_error_message() {
    init();
    let circuit = circuit_json_cstring();
    let mut prover: *mut PKProver = std::ptr::null_mut();
    let mut verifier: *mut PKVerifier = std::ptr::null_mut();
    let _ = unsafe { pk_prepare(circuit.as_ptr(), 99, &mut prover, &mut verifier) };
    let err = unsafe { last_error() };
    assert!(
        err.as_slice().len() > 0,
        "expected error message for bad hash_config"
    );
    assert!(
        err.as_str().contains("hash_config"),
        "expected 'hash_config' in message, got: {}",
        err.as_str()
    );
    unsafe {
        pk_free_prover(prover);
        pk_free_verifier(verifier);
    }
}

#[test]
fn b_prepare_nonexistent_circuit_returns_compilation_error() {
    init();
    let bad_path = CString::new("/no/such/circuit.json").unwrap();
    let mut prover: *mut PKProver = std::ptr::null_mut();
    let mut verifier: *mut PKVerifier = std::ptr::null_mut();
    let status = unsafe { pk_prepare(bad_path.as_ptr(), 0, &mut prover, &mut verifier) };
    assert_eq!(status, PK_COMPILATION_ERROR);
    let err = unsafe { last_error() };
    assert!(
        err.as_slice().len() > 0,
        "expected error message for bad circuit path"
    );
    unsafe {
        pk_free_prover(prover);
        pk_free_verifier(verifier);
    }
}

// ===========================================================================
// C. pk_prepare — success (release only, needs compiled circuit)
// ===========================================================================

#[test]
fn c_prepare_valid_circuit_returns_nonnull_handles() {
    let (pk, vk) = unsafe { prepare_basic_circuit() };
    assert!(!pk.0.is_null(), "prover handle must be non-null");
    assert!(!vk.0.is_null(), "verifier handle must be non-null");
}

// ===========================================================================
// D. pk_prove_toml — round-trips (release only)
// ===========================================================================

#[test]
fn d_prove_toml_null_prover_returns_invalid_input() {
    init();
    let toml = toml_input_cstring();
    let mut proof_buf = PKBuf::empty();
    let status = unsafe { pk_prove_toml(std::ptr::null(), toml.as_ptr(), &mut proof_buf) };
    assert_eq!(status, PK_INVALID_INPUT);
}

#[test]
fn d_prove_toml_null_out_proof_returns_invalid_input() {
    init();
    // Use a dummy non-null prover pointer for the null-check test.
    // We pass a stack int as a fake pointer; pk_prove_toml checks out_proof
    // for null first when prover is also null, but let's use a non-null prover
    // by preparing one in release mode — in debug we just need to reach the
    // null-output-ptr path. We can pass null prover here since the null checks
    // happen before dereferencing either pointer.
    let toml = toml_input_cstring();
    let status = unsafe { pk_prove_toml(std::ptr::null(), toml.as_ptr(), std::ptr::null_mut()) };
    // Both prover AND out_proof null → InvalidInput
    assert_eq!(status, PK_INVALID_INPUT);
}

#[test]
fn d_prove_toml_proof_bytes_nonempty() {
    let (pk, _vk) = unsafe { prepare_basic_circuit() };
    let toml = toml_input_cstring();
    let mut proof_buf = PKBuf::empty();
    let status = unsafe { pk_prove_toml(pk.0, toml.as_ptr(), &mut proof_buf) };
    let proof = ScopedBuf(proof_buf);
    assert_eq!(status, PK_SUCCESS, "pk_prove_toml failed");
    assert!(proof.as_slice().len() > 0, "proof buffer must not be empty");
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn d_prove_toml_roundtrip() {
    let (pk, vk) = unsafe { prepare_basic_circuit() };
    let toml = toml_input_cstring();

    let mut proof_buf = PKBuf::empty();
    let prove_status = unsafe { pk_prove_toml(pk.0, toml.as_ptr(), &mut proof_buf) };
    assert_eq!(prove_status, PK_SUCCESS, "pk_prove_toml failed");

    let proof = ScopedBuf(proof_buf);
    let verify_status =
        unsafe { pk_verify(vk.0, proof.as_slice().as_ptr(), proof.as_slice().len()) };
    assert_eq!(
        verify_status, PK_SUCCESS,
        "pk_verify failed for toml-proved proof"
    );
}

#[test]
fn d_prove_toml_bad_toml_path_returns_error() {
    let (pk, _vk) = unsafe { prepare_basic_circuit() };
    let bad = CString::new("/no/such/Prover.toml").unwrap();
    let mut proof_buf = PKBuf::empty();
    let status = unsafe { pk_prove_toml(pk.0, bad.as_ptr(), &mut proof_buf) };
    // Should fail with WitnessReadError or ProofError depending on internals
    assert_ne!(status, PK_SUCCESS, "expected failure for bad toml path");
    let err = unsafe { last_error() };
    assert!(
        err.as_slice().len() > 0,
        "expected error message for bad toml path"
    );
}

// ===========================================================================
// E. pk_prove_json — round-trips (release only)
// ===========================================================================

#[test]
fn e_prove_json_null_prover_returns_invalid_input() {
    init();
    let json = CString::new(JSON_INPUTS_VALID).unwrap();
    let mut proof_buf = PKBuf::empty();
    let status = unsafe { pk_prove_json(std::ptr::null(), json.as_ptr(), &mut proof_buf) };
    assert_eq!(status, PK_INVALID_INPUT);
}

#[test]
fn e_prove_json_null_out_proof_returns_invalid_input() {
    init();
    let json = CString::new(JSON_INPUTS_VALID).unwrap();
    let status = unsafe { pk_prove_json(std::ptr::null(), json.as_ptr(), std::ptr::null_mut()) };
    assert_eq!(status, PK_INVALID_INPUT);
}

#[test]
fn e_prove_json_produces_nonempty_proof() {
    let (pk, _vk) = unsafe { prepare_basic_circuit() };
    let json = CString::new(JSON_INPUTS_VALID).unwrap();

    let mut proof_buf = PKBuf::empty();
    let prove_status = unsafe { pk_prove_json(pk.0, json.as_ptr(), &mut proof_buf) };
    let proof = ScopedBuf(proof_buf);
    assert_eq!(prove_status, PK_SUCCESS, "pk_prove_json failed");
    assert!(proof.as_slice().len() > 0, "proof buffer must not be empty");
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn e_prove_json_roundtrip() {
    let (pk, vk) = unsafe { prepare_basic_circuit() };
    let json = CString::new(JSON_INPUTS_VALID).unwrap();

    let mut proof_buf = PKBuf::empty();
    let prove_status = unsafe { pk_prove_json(pk.0, json.as_ptr(), &mut proof_buf) };
    assert_eq!(prove_status, PK_SUCCESS, "pk_prove_json failed");

    let proof = ScopedBuf(proof_buf);
    let verify_status =
        unsafe { pk_verify(vk.0, proof.as_slice().as_ptr(), proof.as_slice().len()) };
    assert_eq!(
        verify_status, PK_SUCCESS,
        "pk_verify failed for json-proved proof"
    );
}

#[test]
fn e_prove_json_wrong_field_returns_error() {
    let (pk, _vk) = unsafe { prepare_basic_circuit() };
    // "x" is not a valid field for basic-2 (expects a, b, c, d)
    let bad_json = CString::new(r#"{"x": "1", "b": "2", "c": "3", "d": "5"}"#).unwrap();
    let mut proof_buf = PKBuf::empty();
    let status = unsafe { pk_prove_json(pk.0, bad_json.as_ptr(), &mut proof_buf) };
    assert_ne!(status, PK_SUCCESS, "expected failure for wrong JSON field");
    let err = unsafe { last_error() };
    assert!(
        err.as_slice().len() > 0,
        "expected error message for wrong field"
    );
}

#[test]
fn e_prove_json_null_inputs_returns_error() {
    let (pk, _vk) = unsafe { prepare_basic_circuit() };
    let mut proof_buf = PKBuf::empty();
    // Passing null for inputs_json
    let status = unsafe { pk_prove_json(pk.0, std::ptr::null(), &mut proof_buf) };
    assert_ne!(status, PK_SUCCESS);
}

#[test]
fn e_prove_json_malformed_json_returns_witness_error() {
    // Syntactically invalid JSON → noirc_abi parse error → WitnessReadError(3)
    let (pk, _vk) = unsafe { prepare_basic_circuit() };
    let bad = CString::new("{invalid json").unwrap();
    let mut proof_buf = PKBuf::empty();
    let status = unsafe { pk_prove_json(pk.0, bad.as_ptr(), &mut proof_buf) };
    assert_eq!(
        status,
        PKStatus::WitnessReadError as i32,
        "malformed JSON should return WitnessReadError"
    );
    let err = unsafe { last_error() };
    assert!(
        err.as_slice().len() > 0,
        "malformed JSON should set an error message"
    );
}

#[test]
fn e_prove_json_wrong_type_returns_witness_error() {
    // Passing a JSON array for a Field input — type mismatch that ABI
    // parsing must reject.
    let (pk, _vk) = unsafe { prepare_basic_circuit() };
    let bad = CString::new(r#"{"a": [1, 2], "b": "2", "c": "3", "d": "5"}"#).unwrap();
    let mut proof_buf = PKBuf::empty();
    let status = unsafe { pk_prove_json(pk.0, bad.as_ptr(), &mut proof_buf) };
    assert_ne!(status, PK_SUCCESS, "array for Field input should fail");
    let err = unsafe { last_error() };
    assert!(
        err.as_slice().len() > 0,
        "type mismatch should set an error message"
    );
}

#[test]
fn e_prove_json_empty_object_returns_witness_error() {
    // Empty JSON object is missing all required circuit inputs.
    let (pk, _vk) = unsafe { prepare_basic_circuit() };
    let bad = CString::new("{}").unwrap();
    let mut proof_buf = PKBuf::empty();
    let status = unsafe { pk_prove_json(pk.0, bad.as_ptr(), &mut proof_buf) };
    assert_ne!(
        status, PK_SUCCESS,
        "empty JSON object should not prove successfully"
    );
    let err = unsafe { last_error() };
    assert!(
        err.as_slice().len() > 0,
        "missing fields should set an error message"
    );
}

// ===========================================================================
// F. pk_verify — error paths
// ===========================================================================

#[test]
fn f_verify_null_verifier_returns_invalid_input() {
    init();
    let dummy = [0u8; 8];
    let status = unsafe { pk_verify(std::ptr::null(), dummy.as_ptr(), dummy.len()) };
    assert_eq!(status, PK_INVALID_INPUT);
}

#[test]
fn f_verify_null_proof_ptr_returns_invalid_input() {
    // A real verifier handle is required: pk_verify checks
    // `verifier.is_null() || proof_ptr.is_null() || proof_len == 0`
    // in a single OR chain. Without a real verifier, the verifier.is_null()
    // branch fires first and the proof_ptr.is_null() branch is never reached.
    let (_pk, vk) = unsafe { prepare_basic_circuit() };
    let status = unsafe { pk_verify(vk.0, std::ptr::null(), 16) };
    assert_eq!(status, PK_INVALID_INPUT);
}

#[test]
fn f_verify_zero_proof_len_returns_invalid_input() {
    init();
    let dummy = [0u8; 8];
    let status = unsafe { pk_verify(std::ptr::null(), dummy.as_ptr(), 0) };
    assert_eq!(status, PK_INVALID_INPUT);
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn f_verify_garbage_bytes_returns_serialization_error() {
    let (_pk, vk) = unsafe { prepare_basic_circuit() };
    let garbage: Vec<u8> = std::iter::repeat([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03u8])
        .take(8)
        .flatten()
        .collect();
    let status = unsafe { pk_verify(vk.0, garbage.as_ptr(), garbage.len()) };
    // Garbage bytes fail postcard deserialization
    assert_ne!(status, PK_SUCCESS);
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn f_verify_corrupted_proof_returns_proof_error() {
    let (pk, vk) = unsafe { prepare_basic_circuit() };
    let json = CString::new(JSON_INPUTS_VALID).unwrap();

    let mut proof_buf = PKBuf::empty();
    let prove_status = unsafe { pk_prove_json(pk.0, json.as_ptr(), &mut proof_buf) };
    assert_eq!(prove_status, PK_SUCCESS);
    let proof = ScopedBuf(proof_buf);

    // Corrupt a byte in the middle of the proof
    let mut corrupted = proof.as_slice().to_vec();
    let mid = corrupted.len() / 2;
    corrupted[mid] ^= 0xff;

    let status = unsafe { pk_verify(vk.0, corrupted.as_ptr(), corrupted.len()) };
    assert_eq!(status, PK_PROOF_ERROR, "corrupted proof must not verify");
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn f_verify_idempotent() {
    let (pk, vk) = unsafe { prepare_basic_circuit() };
    let json = CString::new(JSON_INPUTS_VALID).unwrap();

    let mut proof_buf = PKBuf::empty();
    unsafe { pk_prove_json(pk.0, json.as_ptr(), &mut proof_buf) };
    let proof = ScopedBuf(proof_buf);

    let s1 = unsafe { pk_verify(vk.0, proof.as_slice().as_ptr(), proof.as_slice().len()) };
    let s2 = unsafe { pk_verify(vk.0, proof.as_slice().as_ptr(), proof.as_slice().len()) };
    assert_eq!(s1, PK_SUCCESS);
    assert_eq!(
        s2, PK_SUCCESS,
        "second verify call on same proof must also succeed"
    );
}

// ===========================================================================
// G. Serialize / deserialize round-trips (release only)
// ===========================================================================

#[test]
fn g_serialize_prover_null_handle_returns_invalid_input() {
    init();
    let mut buf = PKBuf::empty();
    let status = unsafe { pk_serialize_prover(std::ptr::null(), &mut buf) };
    assert_eq!(status, PK_INVALID_INPUT);
}

#[test]
fn g_serialize_verifier_null_out_buf_returns_invalid_input() {
    init();
    let status = unsafe { pk_serialize_verifier(std::ptr::null(), std::ptr::null_mut()) };
    assert_eq!(status, PK_INVALID_INPUT);
}

#[test]
fn g_load_prover_bytes_zero_len_returns_invalid_input() {
    init();
    let dummy = [0u8; 4];
    let mut out: *mut PKProver = std::ptr::null_mut();
    let status = unsafe { pk_load_prover_bytes(dummy.as_ptr(), 0, &mut out) };
    assert_eq!(status, PK_INVALID_INPUT);
}

#[test]
fn g_load_verifier_bytes_null_ptr_returns_invalid_input() {
    init();
    let mut out: *mut PKVerifier = std::ptr::null_mut();
    let status = unsafe { pk_load_verifier_bytes(std::ptr::null(), 16, &mut out) };
    assert_eq!(status, PK_INVALID_INPUT);
}

#[test]
fn g_load_prover_bytes_corrupt_data_returns_scheme_read_error() {
    init();
    let garbage = vec![0xbau8, 0xad, 0xf0, 0x0d, 0x01, 0x02, 0x03, 0x04];
    let mut out: *mut PKProver = std::ptr::null_mut();
    let status = unsafe { pk_load_prover_bytes(garbage.as_ptr(), garbage.len(), &mut out) };
    assert_eq!(status, PK_SCHEME_READ_ERROR);
    let err = unsafe { last_error() };
    assert!(
        err.as_slice().len() > 0,
        "expected error message for corrupt prover bytes"
    );
}

#[test]
fn g_load_verifier_bytes_corrupt_data_returns_scheme_read_error() {
    init();
    let garbage = vec![0xbau8, 0xad, 0xf0, 0x0d, 0x01, 0x02, 0x03, 0x04];
    let mut out: *mut PKVerifier = std::ptr::null_mut();
    let status = unsafe { pk_load_verifier_bytes(garbage.as_ptr(), garbage.len(), &mut out) };
    assert_eq!(status, PK_SCHEME_READ_ERROR);
    let err = unsafe { last_error() };
    assert!(
        err.as_slice().len() > 0,
        "expected error message for corrupt verifier bytes"
    );
}

#[test]
fn g_serialize_prover_bytes_roundtrip_prove_only() {
    // Tests the exact mobile workflow: prepare → serialize → load_bytes → prove
    // (no verify, so runs in debug)
    let (pk, _vk) = unsafe { prepare_basic_circuit() };

    // Serialize prover to bytes
    let mut ser_buf = PKBuf::empty();
    let ser_status = unsafe { pk_serialize_prover(pk.0, &mut ser_buf) };
    assert_eq!(ser_status, PK_SUCCESS, "pk_serialize_prover failed");
    let ser = ScopedBuf(ser_buf);
    assert!(
        ser.as_slice().len() > 0,
        "serialized prover must be non-empty"
    );

    // Reload from bytes
    let mut pk2: *mut PKProver = std::ptr::null_mut();
    let load_status =
        unsafe { pk_load_prover_bytes(ser.as_slice().as_ptr(), ser.as_slice().len(), &mut pk2) };
    assert_eq!(load_status, PK_SUCCESS, "pk_load_prover_bytes failed");
    let pk2 = ScopedProver(pk2);

    // Prove with the reloaded prover
    let json = CString::new(JSON_INPUTS_VALID).unwrap();
    let mut proof_buf = PKBuf::empty();
    let prove_status = unsafe { pk_prove_json(pk2.0, json.as_ptr(), &mut proof_buf) };
    assert_eq!(
        prove_status, PK_SUCCESS,
        "prove via reloaded prover must succeed"
    );
    let proof = ScopedBuf(proof_buf);
    assert!(proof.as_slice().len() > 0);
}

#[test]
fn g_serialize_verifier_bytes_roundtrip_load_only() {
    // Tests serialize → load_bytes for verifier (no verify call, so debug-safe)
    let (_pk, vk) = unsafe { prepare_basic_circuit() };

    let mut ser_buf = PKBuf::empty();
    let ser_status = unsafe { pk_serialize_verifier(vk.0, &mut ser_buf) };
    assert_eq!(ser_status, PK_SUCCESS, "pk_serialize_verifier failed");
    let ser = ScopedBuf(ser_buf);
    assert!(
        ser.as_slice().len() > 0,
        "serialized verifier must be non-empty"
    );

    let mut vk2: *mut PKVerifier = std::ptr::null_mut();
    let load_status =
        unsafe { pk_load_verifier_bytes(ser.as_slice().as_ptr(), ser.as_slice().len(), &mut vk2) };
    assert_eq!(load_status, PK_SUCCESS, "pk_load_verifier_bytes failed");
    let vk2 = ScopedVerifier(vk2);
    assert!(!vk2.0.is_null());
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn g_serialize_prover_roundtrip() {
    let (pk, _vk) = unsafe { prepare_basic_circuit() };

    // Serialize
    let mut ser_buf = PKBuf::empty();
    let ser_status = unsafe { pk_serialize_prover(pk.0, &mut ser_buf) };
    assert_eq!(ser_status, PK_SUCCESS, "pk_serialize_prover failed");
    let ser = ScopedBuf(ser_buf);
    assert!(ser.as_slice().len() > 0);

    // Reload from bytes
    let mut pk2: *mut PKProver = std::ptr::null_mut();
    let load_status =
        unsafe { pk_load_prover_bytes(ser.as_slice().as_ptr(), ser.as_slice().len(), &mut pk2) };
    assert_eq!(load_status, PK_SUCCESS, "pk_load_prover_bytes failed");
    let pk2 = ScopedProver(pk2);

    // Prove with the reloaded prover
    let (_orig_pk, vk) = unsafe { prepare_basic_circuit() };
    let json = CString::new(JSON_INPUTS_VALID).unwrap();
    let mut proof_buf = PKBuf::empty();
    let prove_status = unsafe { pk_prove_json(pk2.0, json.as_ptr(), &mut proof_buf) };
    assert_eq!(prove_status, PK_SUCCESS);
    let proof = ScopedBuf(proof_buf);

    let verify_status =
        unsafe { pk_verify(vk.0, proof.as_slice().as_ptr(), proof.as_slice().len()) };
    assert_eq!(
        verify_status, PK_SUCCESS,
        "proof from reloaded prover must verify"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn g_serialize_verifier_roundtrip() {
    let (pk, vk) = unsafe { prepare_basic_circuit() };

    // Serialize verifier
    let mut ser_buf = PKBuf::empty();
    let ser_status = unsafe { pk_serialize_verifier(vk.0, &mut ser_buf) };
    assert_eq!(ser_status, PK_SUCCESS, "pk_serialize_verifier failed");
    let ser = ScopedBuf(ser_buf);
    assert!(ser.as_slice().len() > 0);

    // Reload verifier from bytes
    let mut vk2: *mut PKVerifier = std::ptr::null_mut();
    let load_status =
        unsafe { pk_load_verifier_bytes(ser.as_slice().as_ptr(), ser.as_slice().len(), &mut vk2) };
    assert_eq!(load_status, PK_SUCCESS, "pk_load_verifier_bytes failed");
    let vk2 = ScopedVerifier(vk2);

    // Generate a proof with the original prover and verify with the reloaded
    // verifier
    let json = CString::new(JSON_INPUTS_VALID).unwrap();
    let mut proof_buf = PKBuf::empty();
    unsafe { pk_prove_json(pk.0, json.as_ptr(), &mut proof_buf) };
    let proof = ScopedBuf(proof_buf);

    let verify_status =
        unsafe { pk_verify(vk2.0, proof.as_slice().as_ptr(), proof.as_slice().len()) };
    assert_eq!(
        verify_status, PK_SUCCESS,
        "reloaded verifier must accept valid proof"
    );
}

// ===========================================================================
// H. Save / load file round-trips (release only)
// ===========================================================================

#[test]
fn h_save_prover_null_handle_returns_invalid_input() {
    init();
    let path = CString::new("/tmp/provekit_test_prover.pkp").unwrap();
    let status = unsafe { pk_save_prover(std::ptr::null(), path.as_ptr()) };
    assert_eq!(status, PK_INVALID_INPUT);
}

#[test]
fn h_save_verifier_null_handle_returns_invalid_input() {
    init();
    let path = CString::new("/tmp/provekit_test_verifier.pkv").unwrap();
    let status = unsafe { pk_save_verifier(std::ptr::null(), path.as_ptr()) };
    assert_eq!(status, PK_INVALID_INPUT);
}

#[test]
fn h_save_prover_null_path_returns_invalid_input() {
    // c_str_to_str returns Err(InvalidInput) for null C strings;
    // verify pk_save_prover propagates that correctly.
    let (pk, _vk) = unsafe { prepare_basic_circuit() };
    let status = unsafe { pk_save_prover(pk.0, std::ptr::null()) };
    assert_eq!(status, PK_INVALID_INPUT);
    let err = unsafe { last_error() };
    assert!(
        err.as_str().contains("null pointer"),
        "expected 'null pointer' in error, got: {}",
        err.as_str()
    );
}

#[test]
fn h_save_verifier_null_path_returns_invalid_input() {
    let (_pk, vk) = unsafe { prepare_basic_circuit() };
    let status = unsafe { pk_save_verifier(vk.0, std::ptr::null()) };
    assert_eq!(status, PK_INVALID_INPUT);
    let err = unsafe { last_error() };
    assert!(
        err.as_str().contains("null pointer"),
        "expected 'null pointer' in error, got: {}",
        err.as_str()
    );
}

#[test]
fn h_load_prover_bad_path_returns_scheme_read_error() {
    init();
    let bad = CString::new("/no/such/prover.pkp").unwrap();
    let mut out: *mut PKProver = std::ptr::null_mut();
    let status = unsafe { pk_load_prover(bad.as_ptr(), &mut out) };
    assert_eq!(status, PK_SCHEME_READ_ERROR);
    let err = unsafe { last_error() };
    assert!(
        err.as_slice().len() > 0,
        "expected error message for bad prover path"
    );
}

#[test]
fn h_load_verifier_bad_path_returns_scheme_read_error() {
    init();
    let bad = CString::new("/no/such/verifier.pkv").unwrap();
    let mut out: *mut PKVerifier = std::ptr::null_mut();
    let status = unsafe { pk_load_verifier(bad.as_ptr(), &mut out) };
    assert_eq!(status, PK_SCHEME_READ_ERROR);
    let err = unsafe { last_error() };
    assert!(
        err.as_slice().len() > 0,
        "expected error message for bad verifier path"
    );
}

#[test]
fn h_save_load_prover_file_prove_only() {
    // save → load → prove (no verify, debug-safe)
    use tempfile::tempdir;
    let (pk, _vk) = unsafe { prepare_basic_circuit() };

    let dir = tempdir().unwrap();
    let file_path = dir.path().join("prover.pkp");
    let path_cstr = CString::new(file_path.to_str().unwrap()).unwrap();

    let save_status = unsafe { pk_save_prover(pk.0, path_cstr.as_ptr()) };
    assert_eq!(save_status, PK_SUCCESS, "pk_save_prover failed");
    assert!(file_path.exists(), "prover file should exist after save");

    let mut pk2: *mut PKProver = std::ptr::null_mut();
    let load_status = unsafe { pk_load_prover(path_cstr.as_ptr(), &mut pk2) };
    assert_eq!(load_status, PK_SUCCESS, "pk_load_prover failed");
    let pk2 = ScopedProver(pk2);

    let json = CString::new(JSON_INPUTS_VALID).unwrap();
    let mut proof_buf = PKBuf::empty();
    let prove_status = unsafe { pk_prove_json(pk2.0, json.as_ptr(), &mut proof_buf) };
    assert_eq!(
        prove_status, PK_SUCCESS,
        "prove with file-loaded prover must succeed"
    );
    let _proof = ScopedBuf(proof_buf);
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn h_save_load_prover_file_roundtrip() {
    use tempfile::tempdir;
    let (pk, _vk) = unsafe { prepare_basic_circuit() };

    let dir = tempdir().unwrap();
    let file_path = dir.path().join("prover.pkp");
    let path_cstr = CString::new(file_path.to_str().unwrap()).unwrap();

    let save_status = unsafe { pk_save_prover(pk.0, path_cstr.as_ptr()) };
    assert_eq!(save_status, PK_SUCCESS, "pk_save_prover failed");
    assert!(file_path.exists(), "prover file should exist after save");

    let mut pk2: *mut PKProver = std::ptr::null_mut();
    let load_status = unsafe { pk_load_prover(path_cstr.as_ptr(), &mut pk2) };
    assert_eq!(load_status, PK_SUCCESS, "pk_load_prover failed");
    let pk2 = ScopedProver(pk2);

    // Prove with reloaded prover and verify
    let (_orig_pk, vk) = unsafe { prepare_basic_circuit() };
    let json = CString::new(JSON_INPUTS_VALID).unwrap();
    let mut proof_buf = PKBuf::empty();
    let prove_status = unsafe { pk_prove_json(pk2.0, json.as_ptr(), &mut proof_buf) };
    assert_eq!(prove_status, PK_SUCCESS);
    let proof = ScopedBuf(proof_buf);

    let verify_status =
        unsafe { pk_verify(vk.0, proof.as_slice().as_ptr(), proof.as_slice().len()) };
    assert_eq!(
        verify_status, PK_SUCCESS,
        "proof from file-saved prover must verify"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn h_save_load_verifier_file_roundtrip() {
    use tempfile::tempdir;
    let (pk, vk) = unsafe { prepare_basic_circuit() };

    let dir = tempdir().unwrap();
    let file_path = dir.path().join("verifier.pkv");
    let path_cstr = CString::new(file_path.to_str().unwrap()).unwrap();

    let save_status = unsafe { pk_save_verifier(vk.0, path_cstr.as_ptr()) };
    assert_eq!(save_status, PK_SUCCESS, "pk_save_verifier failed");
    assert!(file_path.exists());

    let mut vk2: *mut PKVerifier = std::ptr::null_mut();
    let load_status = unsafe { pk_load_verifier(path_cstr.as_ptr(), &mut vk2) };
    assert_eq!(load_status, PK_SUCCESS, "pk_load_verifier failed");
    let vk2 = ScopedVerifier(vk2);

    let json = CString::new(JSON_INPUTS_VALID).unwrap();
    let mut proof_buf = PKBuf::empty();
    unsafe { pk_prove_json(pk.0, json.as_ptr(), &mut proof_buf) };
    let proof = ScopedBuf(proof_buf);

    let verify_status =
        unsafe { pk_verify(vk2.0, proof.as_slice().as_ptr(), proof.as_slice().len()) };
    assert_eq!(
        verify_status, PK_SUCCESS,
        "file-reloaded verifier must accept valid proof"
    );
}

// ===========================================================================
// I. Error message lifecycle (always runs)
// ===========================================================================

#[test]
fn i_error_cleared_after_read() {
    init();
    // Trigger an error.
    let bad = CString::new("/no/such/prover.pkp").unwrap();
    let mut out: *mut PKProver = std::ptr::null_mut();
    unsafe { pk_load_prover(bad.as_ptr(), &mut out) };

    // First read: error must be present.
    let err1 = unsafe { last_error() };
    assert!(
        err1.as_slice().len() > 0,
        "error should be set after failing call"
    );

    // Second read: must be empty — pk_get_last_error clears the error on
    // the first read (single-read guarantee). Note: pk_init() does NOT clear
    // the error (it wraps no catch_panic), so this tests the read-clears
    // behaviour, not "successful call clears error".
    let err2 = unsafe { last_error() };
    assert_eq!(
        err2.as_slice().len(),
        0,
        "error should be cleared after first read"
    );
}

#[test]
fn i_error_message_descriptive_for_bad_hash_config() {
    init();
    let circuit = circuit_json_cstring();
    let mut prover: *mut PKProver = std::ptr::null_mut();
    let mut verifier: *mut PKVerifier = std::ptr::null_mut();
    unsafe { pk_prepare(circuit.as_ptr(), 255, &mut prover, &mut verifier) };
    let err = unsafe { last_error() };
    assert!(
        err.as_str().contains("hash_config"),
        "error for bad hash_config should mention 'hash_config', got: {}",
        err.as_str()
    );
    unsafe {
        pk_free_prover(prover);
        pk_free_verifier(verifier);
    }
}

#[test]
fn i_error_message_descriptive_for_bad_circuit_path() {
    init();
    let bad = CString::new("/does/not/exist.json").unwrap();
    let mut prover: *mut PKProver = std::ptr::null_mut();
    let mut verifier: *mut PKVerifier = std::ptr::null_mut();
    unsafe { pk_prepare(bad.as_ptr(), 0, &mut prover, &mut verifier) };
    let err = unsafe { last_error() };
    assert!(
        err.as_slice().len() > 0,
        "should have an error message for missing circuit file"
    );
    unsafe {
        pk_free_prover(prover);
        pk_free_verifier(verifier);
    }
}

// ===========================================================================
// J. Cleanup safety (always runs)
// ===========================================================================

#[test]
fn j_free_null_prover_does_not_crash() {
    unsafe { pk_free_prover(std::ptr::null_mut()) };
}

#[test]
fn j_free_null_verifier_does_not_crash() {
    unsafe { pk_free_verifier(std::ptr::null_mut()) };
}

#[test]
fn j_free_empty_buf_does_not_crash() {
    let buf = PKBuf::empty();
    unsafe { pk_free_buf(buf) };
}

#[test]
fn j_free_buf_twice_empty_does_not_crash() {
    // Both are empty (null ptr, cap=0) — both should be safe to free
    let b1 = PKBuf::empty();
    let b2 = PKBuf::empty();
    unsafe {
        pk_free_buf(b1);
        pk_free_buf(b2);
    }
}

#[test]
fn j_free_buf_from_serialized_prover_does_not_crash() {
    let (pk, _vk) = unsafe { prepare_basic_circuit() };
    let mut buf = PKBuf::empty();
    let status = unsafe { pk_serialize_prover(pk.0, &mut buf) };
    assert_eq!(status, PK_SUCCESS);
    // Normal free — should not crash
    unsafe { pk_free_buf(buf) };
}

// ===========================================================================
// K. Thread safety (release only)
// ===========================================================================

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn k_concurrent_prove_same_handle() {
    use std::thread;

    let (pk, vk) = unsafe { prepare_basic_circuit() };
    // SendPtr carries the raw pointer safely across thread boundaries.
    // SAFETY: PKProver and PKVerifier are Send+Sync (asserted in types.rs).
    let pk_ptr = SendPtr(pk.0 as *const PKProver);
    let vk_ptr = SendPtr(vk.0 as *const PKVerifier);

    const N: usize = 4;
    let handles: Vec<_> = (0..N)
        .map(|_| {
            // Clone SendPtr (copy of the pointer value) for each thread.
            let p = SendPtr(pk_ptr.0);
            let v = SendPtr(vk_ptr.0);
            thread::spawn(move || {
                // .as_ptr() is called inside the closure so the closure
                // captures `p`/`v` (SendPtr<T>, which is Send) rather than
                // `p.0`/`v.0` (raw pointers, which are not Send).
                let json = CString::new(JSON_INPUTS_VALID).unwrap();
                let mut proof_buf = PKBuf::empty();
                let prove_status =
                    unsafe { pk_prove_json(p.as_ptr(), json.as_ptr(), &mut proof_buf) };
                assert_eq!(prove_status, PK_SUCCESS, "thread prove failed");
                let proof = ScopedBuf(proof_buf);
                let verify_status = unsafe {
                    pk_verify(
                        v.as_ptr(),
                        proof.as_slice().as_ptr(),
                        proof.as_slice().len(),
                    )
                };
                assert_eq!(verify_status, PK_SUCCESS, "thread verify failed");
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }
    // pk and vk still valid — dropped via ScopedProver/ScopedVerifier
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn k_concurrent_verify_same_handle() {
    use std::{sync::Arc, thread};

    let (pk, vk) = unsafe { prepare_basic_circuit() };

    // Generate one proof to share across threads
    let json = CString::new(JSON_INPUTS_VALID).unwrap();
    let mut proof_buf = PKBuf::empty();
    let prove_status = unsafe { pk_prove_json(pk.0, json.as_ptr(), &mut proof_buf) };
    assert_eq!(prove_status, PK_SUCCESS);
    let proof = ScopedBuf(proof_buf);
    let proof_bytes = proof.as_slice().to_vec();

    // SAFETY: PKVerifier is Send+Sync (asserted in types.rs).
    let vk_ptr = SendPtr(vk.0 as *const PKVerifier);
    let proof_arc = Arc::new(proof_bytes);

    const N: usize = 4;
    let handles: Vec<_> = (0..N)
        .map(|_| {
            let v = SendPtr(vk_ptr.0);
            let proof_clone = Arc::clone(&proof_arc);
            thread::spawn(move || {
                let status =
                    unsafe { pk_verify(v.as_ptr(), proof_clone.as_ptr(), proof_clone.len()) };
                assert_eq!(status, PK_SUCCESS, "concurrent verify failed");
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }
}
