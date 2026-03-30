//! In-memory byte serialization matching the binary file format used by
//! `provekit_common::file::write` / `file::read`.
//!
//! The binary format is: MAGIC(8) + FORMAT(8) + MAJOR(2) + MINOR(2) +
//! compressed postcard data.
//!
//! This module exists because v1's `provekit_common::file` module only
//! supports file-path-based I/O. The FFI handle-based API needs to
//! serialize/deserialize to/from byte buffers.
//!
//! TODO: Extract `serialize_to_bytes` / `deserialize_from_bytes` into
//! `provekit_common::file` and call them from both here and the CLI, to
//! avoid maintaining two copies of the header/compression logic.

use {
    anyhow::{ensure, Context as _, Result},
    bytes::{Buf, BufMut as _, Bytes},
    provekit_common::{file::FileFormat, NoirProof, Prover, Verifier},
    serde::{Deserialize, Serialize},
    std::io::{Read, Write},
};

const HEADER_SIZE: usize = 20;
const MAGIC_BYTES: &[u8] = b"\xDC\xDFOZkp\x01\x00";
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
const XZ_MAGIC: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
const ZSTD_LEVEL: i32 = 3;
const XZ_LEVEL: u32 = 6;

/// Compression algorithm, mirroring `provekit_common::file::bin::Compression`.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Compression {
    Zstd,
    Xz,
}

/// Trait extension to expose which compression a `FileFormat` type uses.
/// We know the mapping from the v1 `provekit_common::file` module:
/// - `NoirProof` → Zstd
/// - `Prover` → Xz
/// - `Verifier` → Zstd
pub(crate) trait FileFormatExt: FileFormat {
    const COMPRESS_ALG: Compression;
}

impl FileFormatExt for NoirProof {
    const COMPRESS_ALG: Compression = Compression::Zstd;
}

impl FileFormatExt for Prover {
    const COMPRESS_ALG: Compression = Compression::Xz;
}

impl FileFormatExt for Verifier {
    const COMPRESS_ALG: Compression = Compression::Zstd;
}

/// Serialize a value to bytes in the same format as `file::write` produces
/// on disk (header + compressed postcard).
pub(crate) fn serialize<T: FileFormatExt + Serialize>(value: &T) -> Result<Vec<u8>> {
    let postcard_data = postcard::to_allocvec(value).context("while encoding to postcard")?;

    let compressed = match T::COMPRESS_ALG {
        Compression::Zstd => zstd::bulk::compress(&postcard_data, ZSTD_LEVEL)
            .context("while compressing with zstd")?,
        Compression::Xz => {
            let mut buf = Vec::new();
            let mut encoder = xz2::write::XzEncoder::new(&mut buf, XZ_LEVEL);
            encoder
                .write_all(&postcard_data)
                .context("while compressing with xz")?;
            encoder.finish().context("while finishing xz stream")?;
            buf
        }
    };

    let mut out = Vec::with_capacity(HEADER_SIZE + compressed.len());
    out.put(MAGIC_BYTES);
    out.put(&T::FORMAT[..]);
    out.put_u16_le(T::VERSION.0);
    out.put_u16_le(T::VERSION.1);
    out.extend_from_slice(&compressed);

    Ok(out)
}

/// Deserialize a value from bytes produced by `serialize` or read from a file
/// written by `file::write`.
pub(crate) fn deserialize<T: FileFormat + for<'a> Deserialize<'a>>(data: &[u8]) -> Result<T> {
    ensure!(
        data.len() > HEADER_SIZE,
        "Data too small ({} bytes, need at least {})",
        data.len(),
        HEADER_SIZE + 1
    );

    let mut header = Bytes::copy_from_slice(&data[..HEADER_SIZE]);

    let mut magic = [0u8; 8];
    header.copy_to_slice(&mut magic);
    ensure!(magic == MAGIC_BYTES, "Invalid magic bytes");

    let mut format = [0u8; 8];
    header.copy_to_slice(&mut format);
    ensure!(format == T::FORMAT, "Invalid format");

    let major = header.get_u16_le();
    let minor = header.get_u16_le();
    ensure!(major == T::VERSION.0, "Incompatible format major version");
    ensure!(minor >= T::VERSION.1, "Incompatible format minor version");

    let compressed = &data[HEADER_SIZE..];
    let decompressed = decompress(compressed)?;

    postcard::from_bytes(&decompressed).context("while decoding from postcard")
}

/// Auto-detect compression format from magic bytes and decompress.
fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    ensure!(data.len() >= 6, "Compressed data too small");

    if data[..4] == ZSTD_MAGIC {
        let mut out = Vec::new();
        let mut decoder = zstd::Decoder::new(std::io::Cursor::new(data))
            .context("while initializing zstd decoder")?;
        decoder
            .read_to_end(&mut out)
            .context("while decompressing zstd data")?;
        Ok(out)
    } else if data[..6] == XZ_MAGIC {
        let mut out = Vec::new();
        let mut decoder = xz2::read::XzDecoder::new(std::io::Cursor::new(data));
        decoder
            .read_to_end(&mut out)
            .context("while decompressing XZ data")?;
        Ok(out)
    } else {
        anyhow::bail!(
            "Unknown compression format (first bytes: {:02X?})",
            &data[..data.len().min(6)]
        );
    }
}
