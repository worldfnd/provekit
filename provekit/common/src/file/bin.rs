use {
    super::{BufExt as _, CountingWriter},
    crate::{utils::human, HashConfig},
    anyhow::{ensure, Context as _, Result},
    bytes::{Buf, BufMut as _, Bytes, BytesMut},
    serde::{Deserialize, Serialize},
    std::{
        fs::File,
        io::{Read, Write},
        path::Path,
    },
    tracing::{info, instrument},
    zstd::stream::{Decoder as ZstdDecoder, Encoder as ZstdEncoder},
};

const ZSTD_COMPRESSION: i32 = zstd::DEFAULT_COMPRESSION_LEVEL;
const HEADER_SIZE: usize = 21;
const MAGIC_BYTES: &[u8] = b"\xDC\xDFOZkp\x01\x00";

/// Write a compressed binary file (fast and small).
#[instrument(skip(value))]
pub fn write_bin<T: Serialize>(
    value: &T,
    path: &Path,
    format: [u8; 8],
    (major, minor): (u16, u16),
    hash_config: Option<HashConfig>,
) -> Result<()> {
    // Open file
    let mut file = File::create(path).context("while creating output file")?;
    let mut file_counter = CountingWriter::new(&mut file);

    // Write header: MAGIC(8) + FORMAT(8) + MAJOR(2) + MINOR(2) + HASH_CONFIG(1)
    let mut header = BytesMut::with_capacity(HEADER_SIZE);
    header.put(MAGIC_BYTES);
    header.put(&format[..]);
    header.put_u16_le(major);
    header.put_u16_le(minor);
    header.put_u8(hash_config.map(|c| c.to_byte()).unwrap_or(0xff));

    file_counter
        .write_all(&header)
        .context("while writing header")?;

    // Open compressor
    let mut compressor = ZstdEncoder::new(&mut file_counter, ZSTD_COMPRESSION)
        .context("while creating compressor")?;
    let mut compressor_counter = CountingWriter::new(&mut compressor);

    // Write Postcard
    postcard::to_io(value, &mut compressor_counter).context("while encoding to postcard")?;

    // Close compressor
    let uncompressed = compressor_counter.count();
    compressor.finish().context("while closing compressor")?;

    // Close file
    let compressed = file_counter.count();
    let size = file.metadata().map(|m| m.len()).ok();
    file.sync_all().context("while syncing output file")?;
    drop(file);

    // Log
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

    // Read hash_config from byte 20
    let hash_config_byte = header.get_u8();
    HashConfig::from_byte(hash_config_byte)
        .with_context(|| format!("Invalid hash config byte: 0x{:02X}", hash_config_byte))
}

/// Read a compressed binary file.
#[instrument(fields(size = path.metadata().map(|m| m.len()).ok()))]
pub fn read_bin<T: for<'a> Deserialize<'a>>(
    path: &Path,
    format: [u8; 8],
    (major, minor): (u16, u16),
) -> Result<T> {
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
    ensure!(
        header.get_u16_le() == major,
        "Incompatible format major version"
    );
    ensure!(
        header.get_u16_le() >= minor,
        "Incompatible format minor version"
    );

    // Skip hash_config byte (already validated in read_hash_config if needed)
    let _hash_config_byte = header.get_u8();

    // Decompressor
    let mut decompressor = ZstdDecoder::new(&mut file).context("while creating decompressor")?;

    // Postcard
    // See <https://github.com/jamesmunns/postcard/pull/212> for the reason for the full uncompressed buffer.
    let mut uncompressed = Vec::new();
    decompressor
        .read_to_end(&mut uncompressed)
        .context("while reading decompressed data")?;
    postcard::from_bytes(&uncompressed).context("while decoding from postcard")
}
