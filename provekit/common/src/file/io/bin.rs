use {
    super::BufExt as _,
    crate::{
        binary_format::{HEADER_SIZE, MAGIC_BYTES, XZ_MAGIC, ZSTD_MAGIC},
        utils::human,
        HashConfig,
    },
    anyhow::{ensure, Context as _, Result},
    bytes::{Buf, BufMut as _, Bytes, BytesMut},
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

/// Compression algorithm for binary file output.
#[derive(Debug, Clone, Copy)]
pub enum Compression {
    Zstd,
    Xz,
}

/// Write a compressed binary file.
#[instrument(skip(value))]
pub fn write_bin<T: Serialize>(
    value: &T,
    path: &Path,
    format: [u8; 8],
    (major, minor): (u16, u16),
    compression: Compression,
    hash_config: Option<HashConfig>,
) -> Result<()> {
    let postcard_data = postcard::to_allocvec(value).context("while encoding to postcard")?;
    let uncompressed = postcard_data.len();

    let compressed_data = match compression {
        Compression::Zstd => {
            zstd::bulk::compress(&postcard_data, 3).context("while compressing with zstd")?
        }
        Compression::Xz => {
            let mut buf = Vec::new();
            let mut encoder = xz2::write::XzEncoder::new(&mut buf, 6);
            encoder
                .write_all(&postcard_data)
                .context("while compressing with xz")?;
            encoder.finish().context("while finishing xz stream")?;
            buf
        }
    };

    let mut file = File::create(path).context("while creating output file")?;

    // Write header: MAGIC(8) + FORMAT(8) + MAJOR(2) + MINOR(2) + HASH_CONFIG(1)
    let mut header = BytesMut::with_capacity(HEADER_SIZE);
    header.put(MAGIC_BYTES);
    header.put(&format[..]);
    header.put_u16_le(major);
    header.put_u16_le(minor);
    header.put_u8(hash_config.map(|c| c.to_byte()).unwrap_or(0xff));

    file.write_all(&header).context("while writing header")?;

    file.write_all(&compressed_data)
        .context("while writing compressed data")?;

    let compressed = HEADER_SIZE + compressed_data.len();
    let size = file.metadata().map(|m| m.len()).ok();
    file.sync_all().context("while syncing output file")?;
    drop(file);

    let ratio = compressed as f64 / uncompressed as f64;
    info!(
        ?path,
        size,
        compressed,
        uncompressed,
        "Wrote {}B bytes to {path:?} ({ratio:.2} compression ratio)",
        human(compressed as f64)
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
#[instrument(fields(size = path.metadata().map(|m| m.len()).ok()))]
pub fn read_bin<T: for<'a> Deserialize<'a>>(
    path: &Path,
    format: [u8; 8],
    (major, minor): (u16, u16),
) -> Result<T> {
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

    let uncompressed = decompress_stream(&mut file)?;

    postcard::from_bytes(&uncompressed).context("while decoding from postcard")
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

    let compressed_data = match compression {
        Compression::Zstd => {
            zstd::bulk::compress(&postcard_data, 3).context("while compressing with zstd")?
        }
        Compression::Xz => {
            let mut buf = Vec::new();
            let mut encoder = xz2::write::XzEncoder::new(&mut buf, 6);
            encoder
                .write_all(&postcard_data)
                .context("while compressing with xz")?;
            encoder.finish().context("while finishing xz stream")?;
            buf
        }
    };

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
        zstd::bulk::decompress(data, usize::MAX).context("while decompressing zstd data")
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

/// Peek at the first bytes to detect compression format, then
/// stream-decompress.
fn decompress_stream(reader: &mut BufReader<File>) -> Result<Vec<u8>> {
    use std::io::BufRead;

    let buf = reader
        .fill_buf()
        .context("while peeking compression magic")?;
    ensure!(
        buf.len() >= 6,
        "File too small to detect compression format"
    );

    let is_zstd = buf[..4] == ZSTD_MAGIC;
    let is_xz = buf[..6] == XZ_MAGIC;

    let mut out = Vec::new();
    if is_zstd {
        let mut decoder = zstd::Decoder::new(reader).context("while initializing zstd decoder")?;
        decoder
            .read_to_end(&mut out)
            .context("while decompressing zstd data")?;
    } else if is_xz {
        let mut decoder = xz2::read::XzDecoder::new(reader);
        decoder
            .read_to_end(&mut out)
            .context("while decompressing XZ data")?;
    } else {
        anyhow::bail!(
            "Unknown compression format (first bytes: {:02X?})",
            &buf[..buf.len().min(6)]
        );
    }

    Ok(out)
}
