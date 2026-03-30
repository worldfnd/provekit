# provekit-ffi Test Plan

## Context

PR #384 rewrites provekit-ffi from file-path API to handle-based API (PKProver/PKVerifier). Review comments from Bisht13 have been addressed (PKError->PKStatus rename, file::serialize for proofs, Prover::abi(), hash_config param, pk_get_last_error, etc). Changes are unstaged on branch `ash/sdk`.

There are currently ZERO tests for FFI functions. Only 2 unit tests exist for mmap_allocator.

## What to test

### 1. Error reporting (`pk_get_last_error`)
- Call an FFI function that fails (e.g., pk_load_prover with bad path)
- Verify pk_get_last_error returns a non-empty UTF-8 message
- Verify calling pk_get_last_error again returns empty (clears on read)
- Verify c_str_to_str null pointer sets error message
- Verify c_str_to_str invalid UTF-8 sets error message

### 2. Prepare flow (`pk_prepare`)
- Compile a noir circuit (use `noir-examples/basic-2/target/basic_2.json`)
- Verify returns Success
- Verify out_prover and out_verifier are non-null
- Test invalid hash_config (e.g., 99) returns InvalidInput with error message
- Test null circuit_path returns error
- Free handles after

### 3. Prove + Verify round-trip
- pk_prepare or pk_load_prover from basic-2
- pk_prove_toml with basic-2 inputs -> get proof bytes
- pk_verify with matching verifier + proof bytes -> expect Success
- pk_verify with corrupted proof bytes -> expect ProofError
- Verify proof bytes are valid .np format (start with magic bytes)

### 4. pk_prove_json
- Same as above but with JSON inputs: `{"x":"5","y":"10"}` (check basic-2 ABI)
- Verify Mavros provers aren't silently rejected (if testable)

### 5. Serialize/Deserialize round-trip
- pk_prepare -> pk_serialize_prover -> pk_load_prover_bytes -> prove
- Verify the re-loaded prover produces valid proofs
- Same for verifier: pk_serialize_verifier -> pk_load_verifier_bytes -> verify

### 6. Save/Load file round-trip
- pk_prepare -> pk_save_prover to temp file -> pk_load_prover from file
- Verify loaded prover works

### 7. PKStatus codes
- Verify each error path returns the expected status code
- Null pointer args -> InvalidInput
- Bad file path -> SchemeReadError
- Invalid proof -> ProofError

### 8. Cleanup
- pk_free_prover/pk_free_verifier/pk_free_buf don't crash
- Double-free protection (null after free)

## How to test

Write tests in `tooling/provekit-ffi/tests/ffi_integration.rs`. Call FFI functions directly from Rust (they're `unsafe extern "C"` but callable from Rust). Use `noir-examples/basic-2` as the test circuit — it's small and already has input files.

The test file needs:
```rust
use provekit_ffi::{pk_init, pk_prepare, pk_prove_toml, pk_verify, ...};
```

Call `pk_init()` once in a test setup. Use `std::ffi::CString` for C string args. Use temp dirs for file I/O tests.

## Important notes

- Branch: `ash/sdk`
- All review changes are unstaged (NOT committed) — check `git diff` to see current state
- The enum is now `PKStatus` (not `PKError`)
- `pk_prepare` now takes `hash_config: c_int` as second param (0=Skyscraper)
- Proofs use `file::serialize` format (standard .np binary), not raw postcard
- `postcard` was removed from FFI Cargo.toml deps
- Test circuit: `noir-examples/basic-2` — may need `cargo run -p provekit -- compile` first if json artifact doesn't exist
