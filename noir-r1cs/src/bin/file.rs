use {
    crate::human,
    anyhow::{Context as _, Result},
    serde::Serialize,
    std::{
        ffi::OsStr,
        fs::File,
        io::{Result as IOResult, Write},
        path::PathBuf,
    },
    tracing::{info, instrument},
    zstd::stream::Encoder as ZstdEncoder,
};

const ZSTD_COMPRESSION: i32 = zstd::DEFAULT_COMPRESSION_LEVEL;
const MAGIC_BYTES: &[u8] = b"\xDC\xDFNWps\x01\x00";

/// Helper to count bytes written to a writer.
struct CountingWriter<T: Write> {
    writer: T,
    count:  usize,
}

/// Write a file with format determined from extension.
#[instrument(skip(value))]
pub fn write<T: Serialize>(value: &T, path: &PathBuf) -> Result<()> {
    match path.extension().and_then(OsStr::to_str) {
        Some("json") => write_json(value, path),
        Some("nps") => write_bin(value, path),
        _ => Err(anyhow::anyhow!(
            "Unsupported file extension, please specify .nps or .json"
        )),
    }
}

/// Write a human readable JSON file (slow and large).
#[instrument(skip(value))]
pub fn write_json<T: Serialize>(value: &T, path: &PathBuf) -> Result<()> {
    // Open file
    let mut file = File::create(path).context("while creating output file")?;
    let mut file_counter = CountingWriter::new(&mut file);

    // Write pretty JSON (for smaller files, use the bin format)
    serde_json::to_writer_pretty(&mut file_counter, value).context("while writing JSON")?;

    let size = file_counter.count();
    file.sync_all().context("while syncing output file")?;
    drop(file);

    info!(
        ?path,
        size,
        "Wrote {}B bytes to {path:?}",
        human(size as f64)
    );
    Ok(())
}

/// Write a compressed binary file (fast and small).
#[instrument(skip(value))]
pub fn write_bin<T: Serialize>(value: &T, path: &PathBuf) -> Result<()> {
    // Open file
    let mut file = File::create(path).context("while creating output file")?;
    let mut file_counter = CountingWriter::new(&mut file);

    // Write magic bytes
    file_counter
        .write_all(MAGIC_BYTES)
        .context("while writing magic bytes")?;

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

impl<T: Write> CountingWriter<T> {
    pub fn new(writer: T) -> Self {
        Self { writer, count: 0 }
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn into_inner(self) -> T {
        self.writer
    }
}

impl<T: Write> Write for CountingWriter<T> {
    fn write(&mut self, buf: &[u8]) -> IOResult<usize> {
        let written = self.writer.write(buf)?;
        self.count += written;
        Ok(written)
    }

    fn flush(&mut self) -> IOResult<()> {
        self.writer.flush()
    }
}
