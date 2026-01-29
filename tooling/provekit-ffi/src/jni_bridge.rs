//! JNI bridge for Android. Exposes ProveKit functions as Java native methods.
//!
//! Kotlin class: `com.provekit.android.ffi.ProveKitFFI`

#[cfg(feature = "android")]
use {
    crate::types::PKError,
    jni::{
        objects::{JClass, JString},
        sys::{jbyteArray, jint},
        JNIEnv,
    },
    provekit_common::{file::read, Prover},
    provekit_prover::Prove,
    std::path::Path,
};

#[cfg(feature = "android")]
#[no_mangle]
pub extern "system" fn Java_com_provekit_android_ffi_ProveKitFFI_nativeInit(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    PKError::Success as jint
}

#[cfg(feature = "android")]
#[no_mangle]
pub extern "system" fn Java_com_provekit_android_ffi_ProveKitFFI_nativeProveToJson<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    prover_path: JString<'local>,
    input_path: JString<'local>,
) -> jbyteArray {
    let prover_str: String = match env.get_string(&prover_path) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };
    let input_str: String = match env.get_string(&input_path) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };

    let json_bytes = match prove_to_json_impl(&prover_str, &input_str) {
        Ok(bytes) => bytes,
        Err(code) => {
            let _ = env.throw_new(
                "com/provekit/android/ffi/ProveKitException",
                format!("Proof generation failed with code: {}", code as i32),
            );
            return std::ptr::null_mut();
        }
    };

    match env.byte_array_from_slice(&json_bytes) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(feature = "android")]
#[no_mangle]
pub extern "system" fn Java_com_provekit_android_ffi_ProveKitFFI_nativeProveToFile<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    prover_path: JString<'local>,
    input_path: JString<'local>,
    out_path: JString<'local>,
) -> jint {
    let prover_str: String = match env.get_string(&prover_path) {
        Ok(s) => s.into(),
        Err(_) => return PKError::InvalidInput as jint,
    };
    let input_str: String = match env.get_string(&input_path) {
        Ok(s) => s.into(),
        Err(_) => return PKError::InvalidInput as jint,
    };
    let out_str: String = match env.get_string(&out_path) {
        Ok(s) => s.into(),
        Err(_) => return PKError::InvalidInput as jint,
    };

    match prove_to_file_impl(&prover_str, &input_str, &out_str) {
        Ok(()) => PKError::Success as jint,
        Err(e) => e as jint,
    }
}

#[cfg(feature = "android")]
fn prove_to_json_impl(prover_path: &str, input_path: &str) -> Result<Vec<u8>, PKError> {
    let prover: Prover = read(Path::new(prover_path)).map_err(|_| PKError::SchemeReadError)?;
    let proof = prover.prove(input_path).map_err(|_| PKError::ProofError)?;
    let json_string = serde_json::to_string(&proof).map_err(|_| PKError::SerializationError)?;
    Ok(json_string.into_bytes())
}

#[cfg(feature = "android")]
fn prove_to_file_impl(prover_path: &str, input_path: &str, out_path: &str) -> Result<(), PKError> {
    let prover: Prover = read(Path::new(prover_path)).map_err(|_| PKError::SchemeReadError)?;
    let proof = prover.prove(input_path).map_err(|_| PKError::ProofError)?;
    provekit_common::file::write(&proof, Path::new(out_path))
        .map_err(|_| PKError::FileWriteError)?;
    Ok(())
}
