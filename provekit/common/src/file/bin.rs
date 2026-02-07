use {
    super::BufExt as _,
    crate::utils::human,
    anyhow::{ensure, Context as _, Result},
    bytes::{Buf, BufMut as _, Bytes, BytesMut},
    serde::{Deserialize, Serialize},
    std::{
        fs::File,
        io::{Read, Write},
        path::Path,
    },
    tracing::{info, instrument},
    xz2::{read::XzDecoder, write::XzEncoder},
};

const HEADER_SIZE: usize = 20;
const MAGIC_BYTES: &[u8] = b"\xDC\xDFOZkp\x01\x00";

/// Write a compressed binary file (uses XZ level 9, slower than zstd2 but much smaller).
#[instrument(skip(value))]
pub fn write_bin<T: Serialize>(
    value: &T,
    path: &Path,
    format: [u8; 8],
    (major, minor): (u16, u16),
) -> Result<()> {
    let postcard_data = postcard::to_allocvec(value).context("while encoding to postcard")?;
    let uncompressed = postcard_data.len();

    let mut compressed_data = Vec::new();
    {
        let mut encoder = XzEncoder::new(&mut compressed_data, 9);
        encoder
            .write_all(&postcard_data)
            .context("while compressing with XZ")?;
        encoder.finish().context("while finishing XZ compression")?;
    }

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

#[instrument(fields(size = path.metadata().map(|m| m.len()).ok()))]
pub fn read_bin<T: for<'a> Deserialize<'a>>(
    path: &Path,
    format: [u8; 8],
    (major, minor): (u16, u16),
) -> Result<T> {
    let mut file = File::open(path).context("while opening input file")?;

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

    let mut decoder = XzDecoder::new(&mut file);
    let mut uncompressed = Vec::new();
    decoder
        .read_to_end(&mut uncompressed)
        .context("while decompressing XZ data")?;

    postcard::from_bytes(&uncompressed).context("while decoding from postcard")
}
