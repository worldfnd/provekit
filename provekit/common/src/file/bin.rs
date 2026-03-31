use {
    super::BufExt as _,
    crate::utils::human,
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

const HEADER_SIZE: usize = 20;
const MAGIC_BYTES: &[u8] = b"\xDC\xDFOZkp\x01\x00";

/// Zstd magic number: `28 B5 2F FD`.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// XZ magic number: `FD 37 7A 58 5A 00`.
const XZ_MAGIC: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];

const ZSTD_LEVEL: i32 = 3;
const XZ_LEVEL: u32 = 6;

/// Compression algorithm for binary file output.
#[derive(Debug, Clone, Copy)]
pub enum Compression {
    Zstd,
    Xz,
}

/// Compress data using the specified compression algorithm.
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
    (major, minor): (u16, u16),
    compression: Compression,
) -> Result<()> {
    let postcard_data = postcard::to_allocvec(value).context("while encoding to postcard")?;
    let uncompressed = postcard_data.len();

    let compressed_data = compress(&postcard_data, compression)?;

    let mut file = File::create(path).context("while creating output file")?;

    let mut header = BytesMut::with_capacity(HEADER_SIZE);
    header.put(MAGIC_BYTES);
    header.put(&format[..]);
    header.put_u16_le(major);
    header.put_u16_le(minor);
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

    let uncompressed = decompress_stream(&mut file)?;

    postcard::from_bytes(&uncompressed).context("while decoding from postcard")
}

/// Serialize a value to bytes using the binary format (header + compressed
/// postcard). Produces the same byte-for-byte output as `write_bin`.
pub fn serialize_to_bytes<T: Serialize>(
    value: &T,
    format: [u8; 8],
    (major, minor): (u16, u16),
    compression: Compression,
) -> Result<Vec<u8>> {
    let postcard_data = postcard::to_allocvec(value).context("while encoding to postcard")?;
    let compressed = compress(&postcard_data, compression)?;

    let mut out = Vec::with_capacity(HEADER_SIZE + compressed.len());
    out.put(MAGIC_BYTES);
    out.put(&format[..]);
    out.put_u16_le(major);
    out.put_u16_le(minor);
    out.extend_from_slice(&compressed);

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

    let mut magic = [0u8; 8];
    header.copy_to_slice(&mut magic);
    ensure!(magic == MAGIC_BYTES, "Invalid magic bytes");

    let mut fmt = [0u8; 8];
    header.copy_to_slice(&mut fmt);
    ensure!(fmt == format, "Invalid format");

    let file_major = header.get_u16_le();
    let file_minor = header.get_u16_le();
    ensure!(file_major == major, "Incompatible format major version");
    ensure!(file_minor >= minor, "Incompatible format minor version");

    let compressed = &data[HEADER_SIZE..];
    let decompressed = decompress_bytes(compressed)?;

    postcard::from_bytes(&decompressed).context("while decoding from postcard")
}

/// Auto-detect compression format from magic bytes and decompress a byte
/// slice.
fn decompress_bytes(data: &[u8]) -> Result<Vec<u8>> {
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
