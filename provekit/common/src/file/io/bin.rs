use {
    super::BufExt as _,
    crate::{
        binary_format::{HEADER_SIZE, MAGIC_BYTES, XZ_MAGIC, ZSTD_MAGIC},
        utils::human,
        HashConfig,
    },
    anyhow::{ensure, Context as _, Result},
    bytes::{Buf, BufMut as _, Bytes},
    serde::{Deserialize, Serialize},
    std::{
        fs::File,
        io::{BufReader, Read, Write},
        path::Path,
    },
    tracing::{info, instrument},
};

/// Byte offset where hash config is stored: MAGIC(8) + FORMAT(8) + MAJOR(2) +
/// MINOR(2) = 20
const HASH_CONFIG_OFFSET: usize = 20;

/// Zstd compression level used for serialization.
const ZSTD_LEVEL: i32 = 3;

/// XZ compression level used for serialization.
const XZ_LEVEL: u32 = 6;

/// Compression algorithm for binary file output.
#[derive(Debug, Clone, Copy)]
pub enum Compression {
    Zstd,
    Xz,
}

/// Compress data using the specified algorithm.
fn compress(data: &[u8], compression: Compression) -> Result<Vec<u8>> {
    match compression {
        Compression::Zstd => {
            zstd::bulk::compress(data, ZSTD_LEVEL).context("while compressing with zstd")
        }
        Compression::Xz => {
            let mut buf = Vec::new();
            let mut encoder = xz2::write::XzEncoder::new(&mut buf, XZ_LEVEL);
            encoder
                .write_all(data)
                .context("while compressing with xz")?;
            encoder.finish().context("while finishing xz stream")?;
            Ok(buf)
        }
    }
}

/// Write a compressed binary file.
#[instrument(skip(value))]
pub fn write_bin<T: Serialize>(
    value: &T,
    path: &Path,
    format: [u8; 8],
    version: (u16, u16),
    compression: Compression,
    hash_config: Option<HashConfig>,
) -> Result<()> {
    let data = serialize_to_bytes(value, format, version, compression, hash_config)?;

    let mut file = File::create(path).context("while creating output file")?;
    file.write_all(&data).context("while writing data")?;
    file.sync_all().context("while syncing output file")?;

    info!(
        ?path,
        size = data.len(),
        "Wrote {}B to {path:?}",
        human(data.len() as f64)
    );
    Ok(())
}

/// Read just the hash_config from the file header (byte 20).
#[instrument(fields(size = path.metadata().map(|m| m.len()).ok()))]
pub fn read_hash_config(
    path: &Path,
    format: [u8; 8],
    (major, minor): (u16, u16),
) -> Result<HashConfig> {
    let mut file = File::open(path).context("while opening input file")?;

    // Read header
    let mut buffer = [0; HEADER_SIZE];
    file.read_exact(&mut buffer)
        .context("while reading header")?;
    let mut header = Bytes::from_owner(buffer);

    ensure!(
        header.get_bytes::<8>() == MAGIC_BYTES,
        "Invalid magic bytes"
    );
    ensure!(header.get_bytes::<8>() == format, "Invalid format");

    let file_major = header.get_u16_le();
    let file_minor = header.get_u16_le();

    ensure!(file_major == major, "Incompatible format major version");
    ensure!(file_minor >= minor, "Incompatible format minor version");

    // Read hash_config at HASH_CONFIG_OFFSET (byte 20)
    debug_assert_eq!(header.remaining(), HEADER_SIZE - HASH_CONFIG_OFFSET);
    let hash_config_byte = header.get_u8();
    HashConfig::from_byte(hash_config_byte)
        .with_context(|| format!("Invalid hash config byte: 0x{:02X}", hash_config_byte))
}

/// Read a compressed binary file, auto-detecting zstd or XZ compression.
///
/// The decompressed bytes are streamed directly into postcard's deserializer
/// instead of being materialized into a single `Vec<u8>`. This keeps peak
/// memory close to the size of the deserialized struct, instead of paying
/// twice (once for the decompressed buffer, once for the parsed value).
///
/// `postcard::from_io` needs a scratch buffer sized to fit the largest
/// `deserialize_bytes` / `deserialize_byte_buf` read it will encounter. For
/// our types that's bounded by the on-disk file size (the largest single
/// borrowed-bytes field — currently the Groth16 proving key — encodes
/// ~1:1 against the compressed file because arkworks-serialized curve points
/// are essentially random). We size the scratch buffer to the file size with
/// a small floor for tiny files.
#[instrument(fields(size = path.metadata().map(|m| m.len()).ok()))]
pub fn read_bin<T: for<'a> Deserialize<'a>>(
    path: &Path,
    format: [u8; 8],
    (major, minor): (u16, u16),
) -> Result<T> {
    use std::io::BufRead;

    let file_size = path.metadata().map(|m| m.len()).unwrap_or(0) as usize;

    let mut file = BufReader::new(File::open(path).context("while opening input file")?);

    let mut buffer = [0; HEADER_SIZE];
    file.read_exact(&mut buffer)
        .context("while reading header")?;
    let mut header = Bytes::from_owner(buffer);
    ensure!(
        header.get_bytes::<8>() == MAGIC_BYTES,
        "Invalid magic bytes"
    );
    ensure!(header.get_bytes::<8>() == format, "Invalid format");
    ensure!(
        header.get_u16_le() == major,
        "Incompatible format major version"
    );
    ensure!(
        header.get_u16_le() >= minor,
        "Incompatible format minor version"
    );

    // Skip hash_config byte (can be read separately via read_hash_config if needed)
    let _hash_config_byte = header.get_u8();

    // Detect compression via magic bytes.
    let peek = file.fill_buf().context("while peeking compression magic")?;
    ensure!(
        peek.len() >= 6,
        "File too small to detect compression format"
    );
    let is_zstd = peek[..4] == ZSTD_MAGIC;
    let is_xz = peek[..6] == XZ_MAGIC;

    // Scratch buffer for postcard streaming. Must be at least as large as
    // the largest single `deserialize_byte_buf` read; in practice this is
    // a few MB at most for our formats. Cap the default at 16 MB so that
    // opening a 1 GB .pkp doesn't allocate a 1 GB scratch on top of the
    // decoder buffer and the parsed value. Floor at 1 MB for tiny .np
    // proofs. Override with `PROVEKIT_SCRATCH_MAX_MB` if a future format
    // needs more.
    const DEFAULT_SCRATCH_CAP: usize = 16 << 20;
    let scratch_cap = std::env::var("PROVEKIT_SCRATCH_MAX_MB")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .and_then(|mb| mb.checked_shl(20))
        .unwrap_or(DEFAULT_SCRATCH_CAP);
    let scratch_size = file_size.min(scratch_cap).max(1 << 20);
    let mut scratch = vec![0u8; scratch_size];

    // Wrap the streaming decoder in a `BufReader` so postcard's per-byte
    // `pop()` calls become fast in-memory reads instead of one syscall each.
    // 256 KB is large enough to amortize syscall overhead without holding more
    // decompressed data in memory than necessary.
    const DECODER_BUF: usize = 256 * 1024;

    // If the cap shrank scratch below the (compressed) file size, the failure
    // mode for an oversized `deserialize_byte_buf` is opaque ("postcard
    // streaming failed"). Attach a hint pointing at the env-var escape hatch
    // so users don't have to guess. Compressed-vs-decompressed is an
    // intentional under-approximation: if the file is small but the
    // decompressed payload contains a huge byte_buf, the hint still fires.
    let scratch_capped = scratch_size < file_size;
    let postcard_err = |stage: &'static str, e: postcard::Error| -> anyhow::Error {
        let err = anyhow::Error::from(e).context(stage);
        if scratch_capped {
            err.context(format!(
                "postcard scratch capped at {} MB (file is {} MB); if a single \
                 `deserialize_byte_buf` read exceeded the cap, raise it with \
                 `PROVEKIT_SCRATCH_MAX_MB=<MB>`",
                scratch_size >> 20,
                file_size >> 20,
            ))
        } else {
            err
        }
    };

    let value = if is_zstd {
        let decoder = zstd::Decoder::new(file).context("while initializing zstd decoder")?;
        let buffered = BufReader::with_capacity(DECODER_BUF, decoder);
        let (value, _) = postcard::from_io::<T, _>((buffered, &mut scratch))
            .map_err(|e| postcard_err("while streaming postcard from zstd", e))?;
        value
    } else if is_xz {
        let decoder = xz2::read::XzDecoder::new(file);
        let buffered = BufReader::with_capacity(DECODER_BUF, decoder);
        let (value, _) = postcard::from_io::<T, _>((buffered, &mut scratch))
            .map_err(|e| postcard_err("while streaming postcard from xz", e))?;
        value
    } else {
        anyhow::bail!(
            "Unknown compression format (first bytes: {:02X?})",
            &peek[..peek.len().min(6)]
        );
    };

    Ok(value)
}

/// Serialize a value to bytes in the same format as `write_bin` (header +
/// compressed postcard). The output is byte-for-byte identical to what
/// `write_bin` would write to disk.
pub fn serialize_to_bytes<T: Serialize>(
    value: &T,
    format: [u8; 8],
    (major, minor): (u16, u16),
    compression: Compression,
    hash_config: Option<HashConfig>,
) -> Result<Vec<u8>> {
    let postcard_data = postcard::to_allocvec(value).context("while encoding to postcard")?;
    let compressed_data = compress(&postcard_data, compression)?;

    let mut out = Vec::with_capacity(HEADER_SIZE + compressed_data.len());
    // Header: MAGIC(8) + FORMAT(8) + MAJOR(2) + MINOR(2) + HASH_CONFIG(1)
    out.put(MAGIC_BYTES);
    out.put(&format[..]);
    out.put_u16_le(major);
    out.put_u16_le(minor);
    out.put_u8(hash_config.map(|c| c.to_byte()).unwrap_or(0xff));
    out.extend_from_slice(&compressed_data);

    Ok(out)
}

/// Deserialize a value from bytes produced by `serialize_to_bytes` or read
/// from a file written by `write_bin`.
pub fn deserialize_from_bytes<T: for<'a> Deserialize<'a>>(
    data: &[u8],
    format: [u8; 8],
    (major, minor): (u16, u16),
) -> Result<T> {
    ensure!(
        data.len() > HEADER_SIZE,
        "Data too small ({} bytes, need at least {})",
        data.len(),
        HEADER_SIZE + 1
    );

    let mut header = Bytes::copy_from_slice(&data[..HEADER_SIZE]);
    ensure!(
        header.get_bytes::<8>() == MAGIC_BYTES,
        "Invalid magic bytes"
    );
    ensure!(header.get_bytes::<8>() == format, "Invalid format");
    ensure!(
        header.get_u16_le() == major,
        "Incompatible format major version"
    );
    ensure!(
        header.get_u16_le() >= minor,
        "Incompatible format minor version"
    );
    let _hash_config_byte = header.get_u8();

    let compressed = &data[HEADER_SIZE..];
    let uncompressed = decompress_bytes(compressed)?;

    postcard::from_bytes(&uncompressed).context("while decoding from postcard")
}

/// Detect compression format from bytes and decompress.
fn decompress_bytes(data: &[u8]) -> Result<Vec<u8>> {
    ensure!(data.len() >= 6, "Data too small to detect compression");

    let is_zstd = data[..4] == ZSTD_MAGIC;
    let is_xz = data[..6] == XZ_MAGIC;

    if is_zstd {
        let mut out = Vec::new();
        let mut decoder = zstd::Decoder::new(data).context("while initializing zstd decoder")?;
        decoder
            .read_to_end(&mut out)
            .context("while decompressing zstd data")?;
        Ok(out)
    } else if is_xz {
        let mut out = Vec::new();
        let mut decoder = xz2::read::XzDecoder::new(data);
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
