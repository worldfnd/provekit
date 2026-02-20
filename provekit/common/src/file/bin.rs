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

/// Write a compressed binary file using zstd (fast compress and decompress).
#[instrument(skip(value))]
pub fn write_bin<T: Serialize>(
    value: &T,
    path: &Path,
    format: [u8; 8],
    (major, minor): (u16, u16),
) -> Result<()> {
    let postcard_data = postcard::to_allocvec(value).context("while encoding to postcard")?;
    let uncompressed = postcard_data.len();

    let compressed_data =
        zstd::bulk::compress(&postcard_data, 3).context("while compressing with zstd")?;

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

    let mut compressed = Vec::new();
    file.read_to_end(&mut compressed)
        .context("while reading compressed data")?;

    let uncompressed = decompress_auto(&compressed)?;

    postcard::from_bytes(&uncompressed).context("while decoding from postcard")
}

/// Auto-detect and decompress data based on magic bytes.
fn decompress_auto(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() >= 4 && data[..4] == ZSTD_MAGIC {
        let mut decoder = zstd::Decoder::new(data).context("while initializing zstd decoder")?;
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .context("while decompressing zstd data")?;
        Ok(out)
    } else if data.len() >= 6 && data[..6] == XZ_MAGIC {
        let mut decoder = xz2::read::XzDecoder::new(data);
        let mut out = Vec::new();
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
