use {
    anyhow::{bail, ensure, Result},
    std::{
        ffi::{CStr, CString},
        os::raw::c_char,
        path::Path,
        ptr,
    },
};

#[repr(C)]
struct NativeBuffer {
    data: *mut u8,
    len:  usize,
}

#[repr(C)]
struct NativeProofBundle {
    public_inputs:    NativeBuffer,
    proof:            NativeBuffer,
    verification_key: NativeBuffer,
}

unsafe extern "C" {
    fn bb_v087_mobile_version() -> *const c_char;
    fn bb_v087_init_local_crs(path: *const c_char, error: *mut *mut c_char) -> i32;
    fn bb_v087_prove(
        circuit: *const c_char,
        witness: *const c_char,
        output: *const c_char,
        bundle: *mut NativeProofBundle,
        error: *mut *mut c_char,
    ) -> i32;
    fn bb_v087_verify(
        public_inputs: *const c_char,
        proof: *const c_char,
        verification_key: *const c_char,
        verified: *mut bool,
        error: *mut *mut c_char,
    ) -> i32;
    fn bb_v087_free_proof_bundle(bundle: *mut NativeProofBundle);
    fn bb_v087_free_error(error: *mut c_char);
}

pub struct ProofBundle {
    pub public_inputs:    Vec<u8>,
    pub proof:            Vec<u8>,
    pub verification_key: Vec<u8>,
}

fn path_string(path: &Path) -> Result<CString> {
    Ok(CString::new(path.to_string_lossy().as_bytes())?)
}

fn status(status: i32, error: *mut c_char) -> Result<()> {
    if status == 0 {
        ensure!(
            error.is_null(),
            "native success returned an error allocation"
        );
        return Ok(());
    }
    let message = if error.is_null() {
        format!("native Barretenberg failed with status {status}")
    } else {
        // SAFETY: The C ABI returns a NUL-terminated allocation on failure.
        let value = unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: This pointer is owned by the caller exactly once.
        unsafe { bb_v087_free_error(error) };
        value
    };
    bail!(message)
}

pub fn initialize_local_crs(path: &Path) -> Result<()> {
    // SAFETY: The version function returns a process-lifetime static string.
    let version = unsafe { CStr::from_ptr(bb_v087_mobile_version()) }.to_str()?;
    ensure!(version == "0.87.0", "linked Barretenberg version mismatch");
    let path = path_string(path)?;
    let mut error = ptr::null_mut();
    // SAFETY: CString is valid for the call and error is an out pointer.
    let result = unsafe { bb_v087_init_local_crs(path.as_ptr(), &mut error) };
    status(result, error)
}

pub fn prove(circuit: &Path, witness: &Path, output: &Path) -> Result<ProofBundle> {
    let circuit = path_string(circuit)?;
    let witness = path_string(witness)?;
    let output = path_string(output)?;
    let mut native = NativeProofBundle {
        public_inputs:    NativeBuffer {
            data: ptr::null_mut(),
            len:  0,
        },
        proof:            NativeBuffer {
            data: ptr::null_mut(),
            len:  0,
        },
        verification_key: NativeBuffer {
            data: ptr::null_mut(),
            len:  0,
        },
    };
    let mut error = ptr::null_mut();
    // SAFETY: All input strings live through the call and native is initialized.
    let result = unsafe {
        bb_v087_prove(
            circuit.as_ptr(),
            witness.as_ptr(),
            output.as_ptr(),
            &mut native,
            &mut error,
        )
    };
    status(result, error)?;
    // SAFETY: Successful native buffers are valid for their reported lengths.
    let bundle = unsafe {
        ProofBundle {
            public_inputs:    std::slice::from_raw_parts(
                native.public_inputs.data,
                native.public_inputs.len,
            )
            .to_vec(),
            proof:            std::slice::from_raw_parts(native.proof.data, native.proof.len)
                .to_vec(),
            verification_key: std::slice::from_raw_parts(
                native.verification_key.data,
                native.verification_key.len,
            )
            .to_vec(),
        }
    };
    // SAFETY: Every native allocation is freed exactly once after copying.
    unsafe { bb_v087_free_proof_bundle(&mut native) };
    Ok(bundle)
}

pub fn verify(public_inputs: &Path, proof: &Path, verification_key: &Path) -> Result<bool> {
    let public_inputs = path_string(public_inputs)?;
    let proof = path_string(proof)?;
    let verification_key = path_string(verification_key)?;
    let mut verified = false;
    let mut error = ptr::null_mut();
    // SAFETY: All strings and output pointers are valid for the call.
    let result = unsafe {
        bb_v087_verify(
            public_inputs.as_ptr(),
            proof.as_ptr(),
            verification_key.as_ptr(),
            &mut verified,
            &mut error,
        )
    };
    status(result, error)?;
    Ok(verified)
}
