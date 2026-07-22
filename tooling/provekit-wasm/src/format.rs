use {
    crate::error::{ErrorCode, WasmError, WasmResult},
    provekit_backend_bn254::{Prover, Verifier},
    provekit_common::{
        binary_format::{
            HEADER_SIZE, MAGIC_BYTES, PROVER_FORMAT, PROVER_VERSION, VERIFIER_FORMAT,
            VERIFIER_VERSION, XZ_MAGIC, ZSTD_MAGIC,
        },
        HashConfig,
    },
    std::io::{Cursor, Read, Write},
};

/// Maximum compressed payload accepted from JavaScript (64 MiB).
pub(crate) const MAX_COMPRESSED_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

/// Maximum uncompressed postcard payload accepted from JavaScript (256 MiB).
pub(crate) const MAX_DECOMPRESSED_ARTIFACT_BYTES: usize = 256 * 1024 * 1024;

pub(crate) fn looks_like_json(data: &[u8]) -> bool {
    matches!(
        data.iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace()),
        Some(b'{')
    )
}

pub(crate) fn ensure_json_artifact_size(data: &[u8], label: &str) -> WasmResult<()> {
    if data.len() > MAX_DECOMPRESSED_ARTIFACT_BYTES {
        return Err(WasmError::new(
            ErrorCode::ArtifactTooLarge,
            format!(
                "JSON {label} artifact is {} bytes, limit is {} bytes",
                data.len(),
                MAX_DECOMPRESSED_ARTIFACT_BYTES
            ),
        ));
    }
    Ok(())
}

fn parse_binary_header_impl<'a>(
    data: &'a [u8],
    expected_format: &[u8; 8],
    (expected_major, min_minor): (u16, u16),
    label: &str,
) -> WasmResult<&'a [u8]> {
    parse_binary_header_with_limit(
        data,
        expected_format,
        (expected_major, min_minor),
        label,
        MAX_COMPRESSED_ARTIFACT_BYTES,
    )
}

fn parse_binary_header_with_limit<'a>(
    data: &'a [u8],
    expected_format: &[u8; 8],
    (expected_major, min_minor): (u16, u16),
    label: &str,
    compressed_limit: usize,
) -> WasmResult<&'a [u8]> {
    if data.len() < HEADER_SIZE {
        return Err(WasmError::new(
            ErrorCode::ArtifactTooShort,
            format!("{label} data too short for binary format"),
        ));
    }
    if data.len() - HEADER_SIZE > compressed_limit {
        return Err(WasmError::new(
            ErrorCode::ArtifactTooLarge,
            format!(
                "Compressed {label} payload is {} bytes, limit is {} bytes",
                data.len() - HEADER_SIZE,
                compressed_limit
            ),
        ));
    }
    if &data[..8] != MAGIC_BYTES {
        return Err(WasmError::new(
            ErrorCode::ArtifactInvalidMagic,
            format!("Invalid magic bytes in {label} data"),
        ));
    }
    if &data[8..16] != expected_format {
        return Err(WasmError::new(
            ErrorCode::ArtifactInvalidFormat,
            format!("Invalid format identifier in {label} data"),
        ));
    }

    let major = u16::from_le_bytes([data[16], data[17]]);
    let minor = u16::from_le_bytes([data[18], data[19]]);
    if major != expected_major {
        return Err(WasmError::new(
            ErrorCode::ArtifactIncompatibleVersion,
            format!(
                "Incompatible {label} format: major version {major}, expected {expected_major}"
            ),
        ));
    }
    if minor < min_minor {
        return Err(WasmError::new(
            ErrorCode::ArtifactIncompatibleVersion,
            format!("Incompatible {label} format: minor version {minor}, expected >= {min_minor}"),
        ));
    }

    let hash_config = data[20];
    if hash_config != 0xff && HashConfig::from_byte(hash_config).is_none() {
        return Err(WasmError::new(
            ErrorCode::ArtifactInvalidFormat,
            format!("Invalid hash config byte in {label} data: 0x{hash_config:02X}"),
        ));
    }

    Ok(&data[HEADER_SIZE..])
}

fn decompress_with_limit(data: &[u8], limit: usize) -> WasmResult<Vec<u8>> {
    if data.len() >= 4 && data[..4] == ZSTD_MAGIC {
        let decoder = ruzstd::decoding::StreamingDecoder::new(Cursor::new(data)).map_err(|e| {
            WasmError::new(
                ErrorCode::ArtifactDecompressionFailed,
                format!("Failed to initialize Zstd decoder: {e}"),
            )
        })?;
        let content_size = decoder.decoder.content_size();
        if content_size > limit as u64 {
            return Err(WasmError::new(
                ErrorCode::ArtifactDecompressedTooLarge,
                format!("Decompressed artifact exceeds {limit} byte limit"),
            ));
        }

        let initial_capacity = usize::try_from(content_size)
            .unwrap_or(0)
            .min(limit)
            .min(16 * 1024 * 1024);
        let mut out = Vec::with_capacity(initial_capacity);
        decoder
            .take((limit as u64).saturating_add(1))
            .read_to_end(&mut out)
            .map_err(|e| {
                WasmError::new(
                    ErrorCode::ArtifactDecompressionFailed,
                    format!("Failed to decompress Zstd data: {e}"),
                )
            })?;
        if out.len() > limit {
            return Err(WasmError::new(
                ErrorCode::ArtifactDecompressedTooLarge,
                format!("Decompressed artifact exceeds {limit} byte limit"),
            ));
        }
        Ok(out)
    } else if data.len() >= 6 && data[..6] == XZ_MAGIC {
        let mut writer = BoundedWriter::new(limit);
        if let Err(error) = lzma_rs::xz_decompress(&mut Cursor::new(data), &mut writer) {
            if writer.exceeded_limit {
                return Err(WasmError::new(
                    ErrorCode::ArtifactDecompressedTooLarge,
                    format!("Decompressed artifact exceeds {limit} byte limit"),
                ));
            }
            return Err(WasmError::new(
                ErrorCode::ArtifactDecompressionFailed,
                format!("Failed to decompress XZ data: {error}"),
            ));
        }
        Ok(writer.output)
    } else {
        Err(WasmError::new(
            ErrorCode::ArtifactUnknownCompression,
            format!(
                "Unknown compression format (first bytes: {:02X?})",
                &data[..data.len().min(6)]
            ),
        ))
    }
}

struct BoundedWriter {
    output:         Vec<u8>,
    limit:          usize,
    exceeded_limit: bool,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            output: Vec::new(),
            limit,
            exceeded_limit: false,
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if buffer.len() > self.limit.saturating_sub(self.output.len()) {
            self.exceeded_limit = true;
            return Err(std::io::Error::other(
                "decompressed artifact limit exceeded",
            ));
        }
        self.output.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Parses a binary prover artifact (`.pkp` format).
pub(crate) fn parse_binary_prover(data: &[u8]) -> WasmResult<Prover> {
    let payload = parse_binary_header_impl(data, &PROVER_FORMAT, PROVER_VERSION, "prover")?;
    let decompressed = decompress_with_limit(payload, MAX_DECOMPRESSED_ARTIFACT_BYTES)?;
    postcard::from_bytes(&decompressed).map_err(|error| {
        WasmError::new(
            ErrorCode::ArtifactDeserializationFailed,
            format!("Failed to deserialize prover data: {error}"),
        )
    })
}

/// Parses a binary verifier artifact (`.pkv` format).
pub(crate) fn parse_binary_verifier(data: &[u8]) -> WasmResult<Verifier> {
    let payload = parse_binary_header_impl(data, &VERIFIER_FORMAT, VERIFIER_VERSION, "verifier")?;
    let decompressed = decompress_with_limit(payload, MAX_DECOMPRESSED_ARTIFACT_BYTES)?;
    postcard::from_bytes(&decompressed).map_err(|error| {
        WasmError::new(
            ErrorCode::ArtifactDeserializationFailed,
            format!("Failed to deserialize verifier data: {error}"),
        )
    })
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
        let parsed =
            parse_binary_header_impl(&data, &PROVER_FORMAT, PROVER_VERSION, "prover").unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn parse_binary_header_rejects_magic_mismatch() {
        let mut data = build_header(PROVER_FORMAT, PROVER_VERSION, 0xff, b"x");
        data[0] ^= 0x01;
        let err =
            parse_binary_header_impl(&data, &PROVER_FORMAT, PROVER_VERSION, "prover").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArtifactInvalidMagic);
        assert!(err.message().contains("Invalid magic bytes in prover data"));
    }

    #[test]
    fn parse_binary_header_rejects_format_mismatch() {
        let data = build_header(VERIFIER_FORMAT, PROVER_VERSION, 0xff, b"x");
        let err =
            parse_binary_header_impl(&data, &PROVER_FORMAT, PROVER_VERSION, "prover").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArtifactInvalidFormat);
    }

    #[test]
    fn parse_binary_header_rejects_major_version_mismatch() {
        let data = build_header(
            PROVER_FORMAT,
            (PROVER_VERSION.0 + 1, PROVER_VERSION.1),
            0xff,
            b"x",
        );
        let err =
            parse_binary_header_impl(&data, &PROVER_FORMAT, PROVER_VERSION, "prover").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArtifactIncompatibleVersion);
    }

    #[test]
    fn parse_binary_header_rejects_minor_version_too_low() {
        let data = build_header(PROVER_FORMAT, PROVER_VERSION, 0xff, b"x");
        let err = parse_binary_header_impl(
            &data,
            &PROVER_FORMAT,
            (PROVER_VERSION.0, PROVER_VERSION.1 + 1),
            "prover",
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArtifactIncompatibleVersion);
    }

    #[test]
    fn parse_binary_header_rejects_data_too_short() {
        let err = parse_binary_header_impl(
            &[0_u8; HEADER_SIZE - 1],
            &PROVER_FORMAT,
            PROVER_VERSION,
            "prover",
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArtifactTooShort);
    }

    #[test]
    fn parse_binary_header_rejects_compressed_payload_over_limit() {
        let data = build_header(PROVER_FORMAT, PROVER_VERSION, 0xff, b"oversized");
        let err =
            parse_binary_header_with_limit(&data, &PROVER_FORMAT, PROVER_VERSION, "prover", 3)
                .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArtifactTooLarge);
    }

    #[test]
    fn parse_binary_header_rejects_invalid_hash_config() {
        let data = build_header(PROVER_FORMAT, PROVER_VERSION, 0xfe, b"x");
        let err =
            parse_binary_header_impl(&data, &PROVER_FORMAT, PROVER_VERSION, "prover").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArtifactInvalidFormat);
    }

    #[test]
    fn decompress_rejects_unknown_magic() {
        let err = decompress_with_limit(b"\x01\x02\x03\x04", 1024).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArtifactUnknownCompression);
    }

    #[test]
    fn decompress_roundtrips_zstd_data() {
        let payload = b"provekit-zstd-roundtrip";
        let compressed = compress_to_vec(payload.as_slice(), CompressionLevel::Fastest);
        assert_eq!(
            decompress_with_limit(&compressed, payload.len()).unwrap(),
            payload
        );
    }

    #[test]
    fn decompress_rejects_zstd_output_over_limit() {
        let compressed = compress_to_vec(b"too-large".as_slice(), CompressionLevel::Fastest);
        let err = decompress_with_limit(&compressed, 3).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArtifactDecompressedTooLarge);
    }

    #[test]
    fn decompress_roundtrips_xz_data() {
        let payload = b"provekit-xz-roundtrip";
        let mut compressed = Vec::new();
        lzma_rs::xz_compress(&mut Cursor::new(payload), &mut compressed).unwrap();
        assert_eq!(
            decompress_with_limit(&compressed, payload.len()).unwrap(),
            payload
        );
    }

    #[test]
    fn decompress_rejects_xz_output_over_limit() {
        let mut compressed = Vec::new();
        lzma_rs::xz_compress(&mut Cursor::new(b"too-large"), &mut compressed).unwrap();
        let err = decompress_with_limit(&compressed, 3).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArtifactDecompressedTooLarge);
    }

    #[test]
    fn json_detection_requires_an_object() {
        assert!(looks_like_json(b" \n {\"key\":1}"));
        assert!(!looks_like_json(MAGIC_BYTES));
        assert!(!looks_like_json(b"not-json"));
    }
}
