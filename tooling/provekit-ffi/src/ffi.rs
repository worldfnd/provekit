//! Main FFI functions for ProveKit.

use {
    crate::{
        types::{PKBuf, PKError},
        utils::c_str_to_str,
    },
    anyhow::{Context, Result},
    provekit_common::{file::read, NoirProofScheme},
    provekit_input_gen::{
        mock_generator::{
            dg1_bytes_with_birthdate_expiry_date, generate_fake_sod, load_csca_mock_private_key,
            load_dsc_mock_private_key,
        },
        parser::{binary::Binary, sod::SOD},
        PassportReader,
    },
    provekit_prover::NoirProofSchemeProver,
    std::{
        fs::File,
        io::Write,
        os::raw::{c_char, c_int},
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    },
};

/// Prove a Noir program and write the proof to a file.
///
/// # Arguments
///
/// * `scheme_path` - Path to the prepared proof scheme (.nps file)
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
    scheme_path: *const c_char,
    input_path: *const c_char,
    out_path: *const c_char,
) -> c_int {
    let result = (|| -> Result<(), PKError> {
        let scheme_path = c_str_to_str(scheme_path)?;
        let input_path = c_str_to_str(input_path)?;
        let out_path = c_str_to_str(out_path)?;

        // Read the scheme file (.nps or .json)
        let mut scheme: NoirProofScheme =
            read(Path::new(scheme_path)).map_err(|_| PKError::SchemeReadError)?;

        // Read the witness/input file (.toml)
        let input_map = scheme
            .read_witness(Path::new(input_path))
            .map_err(|_| PKError::WitnessReadError)?;

        // Generate the proof
        let proof = scheme.prove(&input_map).map_err(|_| PKError::ProofError)?;

        // Write the proof to file
        provekit_common::file::write(&proof, Path::new(out_path))
            .map_err(|_| PKError::FileWriteError)?;

        Ok(())
    })();

    match result {
        Ok(()) => PKError::Success.into(),
        Err(error) => error.into(),
    }
}

/// Prove a Noir program and return the proof as JSON string.
///
/// This function is only available when the "json" feature is enabled.
///
/// # Arguments
///
/// * `scheme_path` - Path to the prepared proof scheme (.nps file)
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
/// - `scheme_path` and `input_path` are valid null-terminated C strings
/// - `out_buf` is a valid pointer to a `PKBuf` structure
/// - The returned buffer is freed using `pk_free_buf`
#[no_mangle]
pub unsafe extern "C" fn pk_prove_to_json(
    scheme_path: *const c_char,
    input_path: *const c_char,
    out_buf: *mut PKBuf,
) -> c_int {
    // Validate inputs
    if out_buf.is_null() {
        return PKError::InvalidInput.into();
    }

    let out_buf = match out_buf.as_mut() {
        Some(buf) => buf,
        None => return PKError::InvalidInput.into(),
    };

    // Initialize output buffer to empty state
    *out_buf = PKBuf::empty();

    let result = (|| -> Result<Vec<u8>, PKError> {
        let scheme_path = c_str_to_str(scheme_path)?;
        let input_path = c_str_to_str(input_path)?;

        // Read the scheme file (.nps or .json)
        let mut scheme: NoirProofScheme =
            read(Path::new(scheme_path)).map_err(|_| PKError::SchemeReadError)?;

        // Read the witness/input file (.toml)
        let input_map = scheme
            .read_witness(Path::new(input_path))
            .map_err(|_| PKError::WitnessReadError)?;

        // Generate the proof
        let proof = scheme.prove(&input_map).map_err(|_| PKError::ProofError)?;

        // Serialize to JSON
        let json_string = serde_json::to_string(&proof).map_err(|_| PKError::SerializationError)?;

        Ok(json_string.into_bytes())
    })();

    match result {
        Ok(json_bytes) => {
            *out_buf = PKBuf::from_vec(json_bytes);
            PKError::Success.into()
        }
        Err(error) => error.into(),
    }
}

/// Converts data from eMRTD document to input file for Noir proof.
///
/// # Arguments
///
/// * `dg1` - Input buffer to get DG1 data from eMRTD
/// * `sod` - Input buffer to get SOD data from eMRTD
/// * `min_age_required` - Minimum age required
/// * `max_age_required` - Maximum age required
/// * `out_path` - Path where to write the input file (.toml)
///
/// # Returns
///
/// Returns `PKError::Success` on success, or an appropriate error code on
/// failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `dg1` is a valid buffer
/// - `sod` is a valid buffer
/// - `out_path` is valid null-terminated C strings
#[no_mangle]
pub unsafe extern "C" fn pk_emrtd_to_input_file(
    dg1: *mut PKBuf,
    sod: *mut PKBuf,
    min_age_required: u8,
    max_age_required: u8,
    out_path: *const c_char,
) -> c_int {
    // Validate inputs
    if dg1.is_null() {
        return PKError::InvalidInput.into();
    }

    if sod.is_null() {
        return PKError::InvalidInput.into();
    }

    let result = (|| -> Result<(), PKError> {
        let out_path = c_str_to_str(out_path)?;

        let dg1 = Binary::new((*dg1).to_vec());
        let sod = SOD::from_der(&mut Binary::new((*sod).to_vec()))
            .map_err(|_| PKError::EMRTDReadError)?;

        let reader = PassportReader {
            dg1,
            sod,
            mockdata: false,
            csca_pubkey: None,
        };
        reader.validate().map_err(|_| PKError::EMRTDReadError)?;

        let inputs = reader.to_circuit_inputs(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|v| v.as_secs())
                .unwrap_or(0),
            min_age_required,
            max_age_required,
            0,
        );

        let mut file = File::create(Path::new(out_path))
            .context("while creating output file")
            .map_err(|_| PKError::FileWriteError)?;
        file.write_all(inputs.unwrap().to_toml_string().as_bytes())
            .context("while writing inputs")
            .map_err(|_| PKError::FileWriteError)?;

        Ok(())
    })();

    match result {
        Ok(()) => PKError::Success.into(),
        Err(error) => error.into(),
    }
}

/// Mocks data from eMRTD document to input file for Noir proof.
///
/// # Arguments
///
/// * `birth_date` - Birth date in format YYMMDD
/// * `expiry_date` - Expiry date in format YYMMDD
/// * `min_age_required` - Minimum age required
/// * `max_age_required` - Maximum age required
/// * `out_path` - Path where to write the input file (.toml)
///
/// # Returns
///
/// Returns `PKError::Success` on success, or an appropriate error code on
/// failure.
///
/// # Safety
///
/// The caller must ensure that:
/// - `birth_date` is valid null-terminated C strings of length 6
/// - `expiry_date` is valid null-terminated C strings of length 6
/// - `out_path` is valid null-terminated C strings
#[no_mangle]
pub unsafe extern "C" fn pk_mock_emrtd_to_input_file(
    birth_date: *const c_char,
    expiry_date: *const c_char,
    min_age_required: u8,
    max_age_required: u8,
    out_path: *const c_char,
) -> c_int {
    let result = (|| -> Result<(), PKError> {
        let out_path = c_str_to_str(out_path)?;

        let birth_date = c_str_to_str(birth_date)?;
        if birth_date.len() != 6 {
            return Err(PKError::InvalidInput);
        }
        let birth_date = [
            birth_date.as_bytes()[0],
            birth_date.as_bytes()[1],
            birth_date.as_bytes()[2],
            birth_date.as_bytes()[3],
            birth_date.as_bytes()[4],
            birth_date.as_bytes()[5],
        ];

        let expiry_date = c_str_to_str(expiry_date)?;
        if expiry_date.len() != 6 {
            return Err(PKError::InvalidInput);
        }
        let expiry_date = [
            expiry_date.as_bytes()[0],
            expiry_date.as_bytes()[1],
            expiry_date.as_bytes()[2],
            expiry_date.as_bytes()[3],
            expiry_date.as_bytes()[4],
            expiry_date.as_bytes()[5],
        ];

        let csca_priv = load_csca_mock_private_key();
        let csca_pub = csca_priv.to_public_key();
        let dsc_priv = load_dsc_mock_private_key();
        let dsc_pub = dsc_priv.to_public_key();

        let dg1 = dg1_bytes_with_birthdate_expiry_date(&birth_date, &expiry_date);
        let sod = generate_fake_sod(&dg1, &dsc_priv, &dsc_pub, &csca_priv, &csca_pub);

        let reader = PassportReader {
            dg1: Binary::new(dg1),
            sod,
            mockdata: true,
            csca_pubkey: Some(csca_pub),
        };
        reader.validate().map_err(|_| PKError::EMRTDReadError)?;

        let inputs = reader.to_circuit_inputs(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|v| v.as_secs())
                .unwrap_or(0),
            min_age_required,
            max_age_required,
            0,
        );

        let mut file = File::create(Path::new(out_path))
            .context("while creating output file")
            .map_err(|_| PKError::FileWriteError)?;
        file.write_all(inputs.unwrap().to_toml_string().as_bytes())
            .context("while writing inputs")
            .map_err(|_| PKError::FileWriteError)?;

        Ok(())
    })();

    match result {
        Ok(()) => PKError::Success.into(),
        Err(error) => error.into(),
    }
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

/// Get the last error message as a C string.
///
/// This function returns a static error message that doesn't need to be freed.
/// For more detailed error information, check the return codes of other
/// functions.
///
/// # Returns
///
/// Returns a null-terminated C string containing the last error message,
/// or a null pointer if no error occurred.
#[no_mangle]
pub extern "C" fn pk_last_error() -> *const c_char {
    // For now, return a generic message. In the future, this could be enhanced
    // to store thread-local error messages.
    b"Check function return codes for error details\0".as_ptr() as *const c_char
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
