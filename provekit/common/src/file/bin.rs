use {
    super::BufExt as _,
    crate::{utils::human, HashConfig},
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

/// Header layout: MAGIC(8) + FORMAT(8) + MAJOR(2) + MINOR(2) + HASH_CONFIG(1) =
/// 21 bytes
const HEADER_SIZE: usize = 21;
const MAGIC_BYTES: &[u8] = b"\xDC\xDFOZkp\x01\x00";
/// Byte offset where hash config is stored: MAGIC(8) + FORMAT(8) + MAJOR(2) +
/// MINOR(2) = 20
const HASH_CONFIG_OFFSET: usize = 20;

/// Zstd magic number: `28 B5 2F FD`.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// XZ magic number: `FD 37 7A 58 5A 00`.
const XZ_MAGIC: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];

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
