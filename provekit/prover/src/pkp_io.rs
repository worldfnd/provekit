//! `.pkp` file I/O with split PK section.
//!
//! For the Groth16 variant the proving key is large (hundreds of MB) and its
//! bytes are essentially uniform random (arkworks-serialized curve points), so
//! they don't compress meaningfully. To avoid materializing the PK in any
//! intermediate buffer during read, the file layout is:
//!
//! ```text
//! [ header (21 bytes) ]
//! [ zstd stream {
//!     [ postcard-encoded Prover (PK serialized as zero-byte placeholder) ]
//!     [ arkworks-encoded ProvingKey ]   // only for Groth16 variant
//!   } ]
//! ```
//!
//! Reading streams from disk → zstd Decoder → postcard for the metadata, then
//! continues from the same decoder into arkworks `CanonicalDeserialize` for
//! the PK. Peak memory tracks the deserialized struct size, not the file
//! size.

use {
    crate::prover_types::Prover,
    anyhow::{ensure, Context, Result},
    ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
    bytes::BufMut as _,
    provekit_common::{
        binary_format::{
            HEADER_SIZE, MAGIC_BYTES, PROVER_FORMAT, PROVER_VERSION, XZ_MAGIC, ZSTD_MAGIC,
        },
        file::MaybeHashAware,
    },
    std::{
        fs::File,
        io::{BufRead, BufReader, Read, Write},
        path::Path,
    },
    tracing::{info, instrument},
};

/// Buffer size for the streaming codec. 256 KB is enough to amortize
/// postcard's per-byte reads/writes; the actual codec throughput is bounded
/// by zstd, not by buffer size.
const DECODER_BUF: usize = 256 * 1024;
const ENCODER_BUF: usize = DECODER_BUF;

/// Zstd compression level matching the rest of the file IO layer.
const ZSTD_LEVEL: i32 = 3;

/// Write a `Prover` to disk in the .pkp format.
#[instrument(skip(prover), fields(path = %path.display()))]
pub fn write_pkp(prover: &Prover, path: &Path) -> Result<()> {
    let file = File::create(path).context("while creating output file")?;
    let mut writer =
        write_pkp_to_writer(prover, std::io::BufWriter::with_capacity(ENCODER_BUF, file))?;
    writer.flush().context("while flushing writer")?;
    let inner = writer
        .into_inner()
        .context("while flushing buffered writer")?;
    inner.sync_all().context("while syncing output file")?;

    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    info!(?path, size, "Wrote .pkp");
    Ok(())
}

fn write_pkp_to_writer<W: Write>(prover: &Prover, mut writer: W) -> Result<W> {
    let hash_config = prover.maybe_hash_config();
    let (major, minor) = PROVER_VERSION;

    // Header: MAGIC(8) + FORMAT(8) + MAJOR(2) + MINOR(2) + HASH_CONFIG(1)
    let mut header = Vec::with_capacity(HEADER_SIZE);
    header.put(MAGIC_BYTES);
    header.put(&PROVER_FORMAT[..]);
    header.put_u16_le(major);
    header.put_u16_le(minor);
    header.put_u8(hash_config.map(|c| c.to_byte()).unwrap_or(0xff));
    writer.write_all(&header).context("while writing header")?;

    // Single zstd stream containing the postcard-encoded Prover (PK is a
    // zero-byte placeholder thanks to `ProvingKey`'s custom Serialize) and,
    // for the Groth16 variant, the raw arkworks-encoded PK appended after.
    let mut encoder =
        zstd::Encoder::new(writer, ZSTD_LEVEL).context("while initializing zstd encoder")?;

    // Postcard-encode the Prover into a temporary buffer, then write it. The
    // metadata is small (R1CS + builders + ABI), so this allocation is OK.
    let postcard_bytes = postcard::to_allocvec(prover).context("while postcard-encoding Prover")?;
    encoder
        .write_all(&postcard_bytes)
        .context("while writing postcard payload")?;

    // For Groth16, append the raw arkworks PK directly into the same zstd
    // stream. arkworks writes incrementally so we never materialize the full
    // PK as a `Vec<u8>`.
    if let Prover::Groth16(g) = prover {
        g.groth16_pk
            .serialize_uncompressed(&mut encoder)
            .context("while writing arkworks-encoded ProvingKey")?;
    }

    encoder.finish().context("while finishing zstd stream")
}

/// Read a `Prover` from disk in the .pkp format.
#[instrument(fields(path = %path.display(), size = path.metadata().map(|m| m.len()).ok()))]
pub fn read_pkp(path: &Path) -> Result<Prover> {
    let file = BufReader::new(File::open(path).context("while opening input file")?);
    read_pkp_from_reader(file)
}

/// Deserialize a `Prover` from in-memory bytes produced by [`serialize_pkp`]
/// or read from a `.pkp` file.
pub fn deserialize_pkp(data: &[u8]) -> Result<Prover> {
    read_pkp_from_reader(std::io::Cursor::new(data))
}

/// Serialize a `Prover` to bytes in the same layout as a `.pkp` file. The
/// output is byte-for-byte identical to what [`write_pkp`] writes to disk.
pub fn serialize_pkp(prover: &Prover) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_pkp_to_writer(prover, &mut out)?;
    Ok(out)
}

fn read_pkp_from_reader<R: Read + BufRead>(mut reader: R) -> Result<Prover> {
    // Header layout: MAGIC(8) + FORMAT(8) + MAJOR(2) + MINOR(2) + HASH_CONFIG(1)
    let mut header_bytes = [0u8; HEADER_SIZE];
    reader
        .read_exact(&mut header_bytes)
        .context("while reading header")?;
    ensure!(&header_bytes[0..8] == MAGIC_BYTES, "Invalid magic bytes");
    ensure!(header_bytes[8..16] == PROVER_FORMAT, "Invalid format");
    let file_major = u16::from_le_bytes([header_bytes[16], header_bytes[17]]);
    let file_minor = u16::from_le_bytes([header_bytes[18], header_bytes[19]]);
    ensure!(
        file_major == PROVER_VERSION.0,
        "Incompatible major version: file is v{}.{}, this build expects v{}.{}",
        file_major,
        file_minor,
        PROVER_VERSION.0,
        PROVER_VERSION.1,
    );
    ensure!(
        file_minor >= PROVER_VERSION.1,
        "Incompatible minor version: file is v{}.{}, this build requires v{}.{} or newer",
        file_major,
        file_minor,
        PROVER_VERSION.0,
        PROVER_VERSION.1,
    );
    let _hash_config = header_bytes[20];

    // Detect compression
    let peek = reader
        .fill_buf()
        .context("while peeking compression magic")?;
    ensure!(peek.len() >= 6, "File too small to detect compression");
    let is_zstd = peek[..4] == ZSTD_MAGIC;
    let is_xz = peek[..6] == XZ_MAGIC;
    ensure!(
        is_zstd || is_xz,
        "Unknown compression format (first bytes: {:02X?})",
        &peek[..6]
    );

    if is_zstd {
        let decoder = zstd::Decoder::new(reader).context("while initializing zstd decoder")?;
        read_split_stream(decoder)
    } else {
        let decoder = xz2::read::XzDecoder::new(reader);
        read_split_stream(decoder)
    }
}

/// Drive the postcard streaming + arkworks streaming reads off a single
/// `Read`. Generic over the decoder type so zstd and xz reuse the same logic.
fn read_split_stream<R: Read>(decoder: R) -> Result<Prover> {
    let buffered = BufReader::with_capacity(DECODER_BUF, decoder);

    // postcard streams the metadata; the PK field deserializes to
    // `ProvingKey::empty()` (the custom serde adapter consumes zero bytes
    // for it). 1 MB scratch is enough — no other field uses
    // `deserialize_bytes` / `deserialize_byte_buf`.
    let mut scratch = vec![0u8; 1024 * 1024];
    let (mut prover, (buffered, _)): (Prover, _) =
        postcard::from_io((buffered, scratch.as_mut_slice()))
            .context("while postcard-decoding Prover")?;

    // Phase 2: for Groth16, fill in the real PK by streaming arkworks bytes
    // directly off the same decoder.
    if let Prover::Groth16(ref mut g) = prover {
        let pk = provekit_groth16::ProvingKey::deserialize_uncompressed_unchecked(buffered)
            .context("while reading arkworks-encoded ProvingKey")?;
        g.groth16_pk = pk;
    }

    Ok(prover)
}
