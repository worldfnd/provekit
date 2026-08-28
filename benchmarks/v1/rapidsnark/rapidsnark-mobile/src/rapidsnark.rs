//! Minimal safe wrapper around the pinned iden3 Rapidsnark C ABI.
//!
//! Adapted from `zkmopro/rust-rapidsnark` revision
//! `df3831a8c24e25c9a7e0a8684e1b3784e02b57f2` (MIT OR Apache-2.0). The
//! upstream crate's native-binary host no longer resolves, so this benchmark
//! links the same libraries built from the campaign's pinned iden3 source.

use {
    anyhow::{anyhow, Result},
    std::{
        ffi::{c_char, c_ulong, c_void, CStr, CString},
        ptr,
    },
};

#[derive(Debug)]
pub struct ProofResult {
    pub proof:          String,
    pub public_signals: String,
}

unsafe extern "C" {
    fn groth16_prover_zkey_file(
        zkey_file_path: *const c_char,
        wtns_buffer: *const c_void,
        wtns_size: u64,
        proof_buffer: *mut c_char,
        proof_size: *mut u64,
        public_buffer: *mut c_char,
        public_size: *mut u64,
        error_msg: *mut c_char,
        error_msg_maxsize: u64,
    ) -> i32;

    fn groth16_verify(
        proof: *const c_char,
        inputs: *const c_char,
        verification_key: *const c_char,
        error_msg: *mut c_char,
        error_msg_maxsize: c_ulong,
    ) -> i32;
}

pub fn verify(proof: &ProofResult, verification_key: &str) -> Result<bool> {
    let proof_json =
        CString::new(proof.proof.as_str()).map_err(|_| anyhow!("proof contains a NUL"))?;
    let public_json = CString::new(proof.public_signals.as_str())
        .map_err(|_| anyhow!("public signals contain a NUL"))?;
    let verification_key =
        CString::new(verification_key).map_err(|_| anyhow!("verification key contains a NUL"))?;
    let mut error = vec![0_u8; 1024];

    // SAFETY: All inputs are valid NUL-terminated strings and the writable
    // error buffer remains live for the duration of the native call.
    let status = unsafe {
        groth16_verify(
            proof_json.as_ptr(),
            public_json.as_ptr(),
            verification_key.as_ptr(),
            error.as_mut_ptr().cast::<c_char>(),
            error.len() as c_ulong,
        )
    };
    if status == 2 {
        // SAFETY: The zero-initialized buffer is NUL-terminated.
        let message = unsafe { CStr::from_ptr(error.as_ptr().cast::<c_char>()) }.to_string_lossy();
        return Err(anyhow!("Rapidsnark verification error: {message}"));
    }
    Ok(status == 0)
}

pub fn prove(zkey_path: &str, witness: &[u8]) -> Result<ProofResult> {
    let zkey_path =
        CString::new(zkey_path).map_err(|_| anyhow!("zkey path contains an interior NUL"))?;
    let mut proof = vec![0_u8; 4 * 1024 * 1024];
    let mut proof_size = proof.len() as u64;
    let mut public = vec![0_u8; 4 * 1024 * 1024];
    let mut public_size = public.len() as u64;
    let mut error = vec![0_u8; 1024];

    // SAFETY: All pointers reference live buffers for the duration of the call.
    // Output capacities are provided to the C ABI, the zkey is NUL-terminated,
    // and the frozen witness bytes are passed with their exact length.
    let status = unsafe {
        groth16_prover_zkey_file(
            zkey_path.as_ptr(),
            witness.as_ptr().cast::<c_void>(),
            witness.len() as u64,
            proof.as_mut_ptr().cast::<c_char>(),
            &mut proof_size,
            public.as_mut_ptr().cast::<c_char>(),
            &mut public_size,
            error.as_mut_ptr().cast::<c_char>(),
            error.len() as u64,
        )
    };
    if status != 0 {
        // SAFETY: The error buffer was zero-initialized, so it remains
        // NUL-terminated even if the native library writes no message.
        let message = unsafe { CStr::from_ptr(error.as_ptr().cast::<c_char>()) }.to_string_lossy();
        return Err(anyhow!("Rapidsnark failed with status {status}: {message}"));
    }

    fn output_string(bytes: &[u8], declared_size: u64, name: &str) -> Result<String> {
        let size = usize::try_from(declared_size).map_err(|_| anyhow!("{name} size overflow"))?;
        let bounded = bytes
            .get(..size.min(bytes.len()))
            .ok_or_else(|| anyhow!("{name} output size is invalid"))?;
        let end = bounded
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bounded.len());
        String::from_utf8(bounded[..end].to_vec())
            .map_err(|error| anyhow!("{name} output is not UTF-8: {error}"))
    }

    let result = ProofResult {
        proof:          output_string(&proof, proof_size, "proof")?,
        public_signals: output_string(&public, public_size, "public signals")?,
    };
    black_box_ptrs(&result);
    Ok(result)
}

#[inline(never)]
fn black_box_ptrs(result: &ProofResult) {
    std::hint::black_box(result.proof.as_ptr());
    std::hint::black_box(result.public_signals.as_ptr());
    std::hint::black_box(ptr::null::<u8>());
}
