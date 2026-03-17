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

pub(crate) fn parse_binary_header<'a>(
    data: &'a [u8],
    expected_format: &[u8; 8],
    (expected_major, min_minor): (u16, u16),
    label: &str,
) -> Result<&'a [u8], JsError> {
    parse_binary_header_impl(data, expected_format, (expected_major, min_minor), label)
        .map_err(|msg| JsError::new(&msg))
}

fn parse_binary_header_impl<'a>(
    data: &'a [u8],
    expected_format: &[u8; 8],
    (expected_major, min_minor): (u16, u16),
    label: &str,
) -> Result<&'a [u8], String> {
    if data.len() < HEADER_SIZE {
        return Err(format!("{label} data too short for binary format"));
    }
    if &data[..8] != MAGIC_BYTES {
        return Err(format!("Invalid magic bytes in {label} data"));
    }
    if &data[8..16] != expected_format {
        return Err(format!("Invalid format identifier in {label} data"));
    }

    let major = u16::from_le_bytes([data[16], data[17]]);
    let minor = u16::from_le_bytes([data[18], data[19]]);
    if major != expected_major {
        return Err(format!(
            "Incompatible {label} format: major version {major}, expected {expected_major}"
        ));
    }
    if minor < min_minor {
        return Err(format!(
            "Incompatible {label} format: minor version {minor}, expected >= {min_minor}"
        ));
    }

    Ok(&data[HEADER_SIZE..])
}

pub(crate) fn decompress(data: &[u8]) -> Result<Vec<u8>, JsError> {
    decompress_impl(data).map_err(|msg| JsError::new(&msg))
}

fn decompress_impl(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() >= 4 && data[..4] == ZSTD_MAGIC {
        let mut decoder = ruzstd::decoding::StreamingDecoder::new(std::io::Cursor::new(data))
            .map_err(|e| format!("Failed to init Zstd decoder: {e}"))?;
        let hint = usize::try_from(decoder.decoder.content_size()).unwrap_or(0);
        let mut out = Vec::with_capacity(hint);
        std::io::Read::read_to_end(&mut decoder, &mut out)
            .map_err(|e| format!("Failed to decompress Zstd data: {e}"))?;
        Ok(out)
    } else if data.len() >= 6 && data[..6] == XZ_MAGIC {
        let mut out = Vec::new();
        lzma_rs::xz_decompress(&mut std::io::Cursor::new(data), &mut out)
            .map_err(|e| format!("Failed to decompress XZ data: {e}"))?;
        Ok(out)
    } else {
        Err(format!(
            "Unknown compression format (first bytes: {:02X?})",
            &data[..data.len().min(6)]
        ))
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

#[cfg(test)]
mod tests {
    use {
        super::*,
        ruzstd::encoding::{compress_to_vec, CompressionLevel},
    };

    fn build_header(
        format: [u8; 8],
        version: (u16, u16),
        hash_config: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(HEADER_SIZE + payload.len());
        data.extend_from_slice(MAGIC_BYTES);
        data.extend_from_slice(&format);
        data.extend_from_slice(&version.0.to_le_bytes());
        data.extend_from_slice(&version.1.to_le_bytes());
        data.push(hash_config);
        data.extend_from_slice(payload);
        data
    }

    #[test]
    fn parse_binary_header_accepts_valid_header() {
        let payload = b"payload-bytes";
        let data = build_header(PROVER_FORMAT, PROVER_VERSION, 0xff, payload);

        let parsed = parse_binary_header(&data, &PROVER_FORMAT, PROVER_VERSION, "prover").unwrap();

        assert_eq!(parsed, payload);
    }

    #[test]
    fn parse_binary_header_rejects_magic_mismatch() {
        let mut data = build_header(PROVER_FORMAT, PROVER_VERSION, 0xff, b"x");
        data[0] ^= 0x01;

        let err =
            parse_binary_header_impl(&data, &PROVER_FORMAT, PROVER_VERSION, "prover").unwrap_err();
        assert!(err.contains("Invalid magic bytes in prover data"));
    }

    #[test]
    fn parse_binary_header_rejects_format_mismatch() {
        let data = build_header(VERIFIER_FORMAT, PROVER_VERSION, 0xff, b"x");

        let err =
            parse_binary_header_impl(&data, &PROVER_FORMAT, PROVER_VERSION, "prover").unwrap_err();
        assert!(err.contains("Invalid format identifier in prover data"));
    }

    #[test]
    fn parse_binary_header_rejects_major_version_mismatch() {
        let bad_major = (PROVER_VERSION.0 + 1, PROVER_VERSION.1);
        let data = build_header(PROVER_FORMAT, bad_major, 0xff, b"x");

        let err =
            parse_binary_header_impl(&data, &PROVER_FORMAT, PROVER_VERSION, "prover").unwrap_err();
        assert!(err.contains("Incompatible prover format: major version"));
    }

    #[test]
    fn parse_binary_header_rejects_minor_version_too_low() {
        let min_minor = PROVER_VERSION.1 + 1;
        let data = build_header(PROVER_FORMAT, PROVER_VERSION, 0xff, b"x");

        let err = parse_binary_header_impl(
            &data,
            &PROVER_FORMAT,
            (PROVER_VERSION.0, min_minor),
            "prover",
        )
        .unwrap_err();
        assert!(err.contains("Incompatible prover format: minor version"));
    }

    #[test]
    fn parse_binary_header_rejects_data_too_short() {
        let too_short = vec![0_u8; HEADER_SIZE - 1];

        let err = parse_binary_header_impl(&too_short, &PROVER_FORMAT, PROVER_VERSION, "prover")
            .unwrap_err();
        assert!(err.contains("prover data too short for binary format"));
    }

    #[test]
    fn decompress_rejects_unknown_magic() {
        let err = decompress_impl(b"\x01\x02\x03\x04").unwrap_err();
        assert!(err.contains("Unknown compression format"));
    }

    #[test]
    fn decompress_roundtrips_zstd_data() {
        let payload = b"provekit-zstd-roundtrip";
        let compressed = compress_to_vec(payload.as_slice(), CompressionLevel::Fastest);

        assert_eq!(&compressed[..4], ZSTD_MAGIC.as_slice());

        let decompressed = decompress_impl(&compressed).unwrap();
        assert_eq!(decompressed, payload);
    }

    #[test]
    fn decompress_roundtrips_xz_data() {
        let payload = b"provekit-xz-roundtrip";
        let mut compressed = Vec::new();
        lzma_rs::xz_compress(&mut std::io::Cursor::new(payload), &mut compressed).unwrap();

        assert_eq!(&compressed[..6], XZ_MAGIC.as_slice());

        let decompressed = decompress_impl(&compressed).unwrap();
        assert_eq!(decompressed, payload);
    }
}
