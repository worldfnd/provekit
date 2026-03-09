use {
    provekit_common::{
        binary_format::{
            HEADER_SIZE, MAGIC_BYTES, PROVER_FORMAT, PROVER_VERSION, VERIFIER_FORMAT,
            VERIFIER_VERSION, XZ_MAGIC, ZSTD_MAGIC,
        },
        Prover, Verifier,
    },
    wasm_bindgen::prelude::*,
};

/// Validate a binary artifact header and return the payload after the header.
///
/// Checks magic bytes, format identifier, and version compatibility
/// (major must match exactly, minor must be >= expected minimum).
fn parse_binary_header<'a>(
    data: &'a [u8],
    expected_format: &[u8; 8],
    (expected_major, min_minor): (u16, u16),
    label: &str,
) -> Result<&'a [u8], JsError> {
    if data.len() < HEADER_SIZE {
        return Err(JsError::new(&format!(
            "{label} data too short for binary format"
        )));
    }
    if &data[..8] != MAGIC_BYTES {
        return Err(JsError::new(&format!(
            "Invalid magic bytes in {label} data"
        )));
    }
    if &data[8..16] != expected_format {
        return Err(JsError::new(&format!(
            "Invalid format identifier in {label} data"
        )));
    }

    let major = u16::from_le_bytes([data[16], data[17]]);
    let minor = u16::from_le_bytes([data[18], data[19]]);
    if major != expected_major {
        return Err(JsError::new(&format!(
            "Incompatible {label} format: major version {major}, expected {expected_major}"
        )));
    }
    if minor < min_minor {
        return Err(JsError::new(&format!(
            "Incompatible {label} format: minor version {minor}, expected >= {min_minor}"
        )));
    }

    Ok(&data[HEADER_SIZE..])
}

/// Auto-detect compression (Zstd or XZ) and decompress.
fn decompress(data: &[u8]) -> Result<Vec<u8>, JsError> {
    if data.len() >= 4 && data[..4] == ZSTD_MAGIC {
        let mut decoder = ruzstd::decoding::StreamingDecoder::new(std::io::Cursor::new(data))
            .map_err(|e| JsError::new(&format!("Failed to init Zstd decoder: {e}")))?;
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut out)
            .map_err(|e| JsError::new(&format!("Failed to decompress Zstd data: {e}")))?;
        Ok(out)
    } else if data.len() >= 6 && data[..6] == XZ_MAGIC {
        let mut out = Vec::new();
        lzma_rs::xz_decompress(&mut std::io::Cursor::new(data), &mut out)
            .map_err(|e| JsError::new(&format!("Failed to decompress XZ data: {e}")))?;
        Ok(out)
    } else {
        Err(JsError::new(&format!(
            "Unknown compression format (first bytes: {:02X?})",
            &data[..data.len().min(6)]
        )))
    }
}

/// Parses a binary prover artifact (.pkp format).
pub fn parse_binary_prover(data: &[u8]) -> Result<Prover, JsError> {
    let payload = parse_binary_header(data, &PROVER_FORMAT, PROVER_VERSION, "prover")?;
    let decompressed = decompress(payload)?;
    postcard::from_bytes(&decompressed)
        .map_err(|err| JsError::new(&format!("Failed to deserialize prover data: {err}")))
}

/// Parses a binary verifier artifact (.pkv format).
pub fn parse_binary_verifier(data: &[u8]) -> Result<Verifier, JsError> {
    let payload = parse_binary_header(data, &VERIFIER_FORMAT, VERIFIER_VERSION, "verifier")?;
    let decompressed = decompress(payload)?;
    postcard::from_bytes(&decompressed)
        .map_err(|err| JsError::new(&format!("Failed to deserialize verifier data: {err}")))
}
