use {
    super::CountingWriter,
    crate::utils::human,
    anyhow::{Context as _, Result},
    serde::{Deserialize, Serialize},
    std::{fs::File, path::Path},
    tracing::{info, instrument},
};

/// Write a human readable JSON file (slow and large).
#[instrument(skip(value))]
pub fn write_json<T: Serialize>(value: &T, path: &Path) -> Result<()> {
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

/// Read a JSON file.
#[instrument(fields(size = path.metadata().map(|m| m.len()).ok()))]
pub fn read_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T> {
    let mut file = File::open(path).context("while opening input file")?;
    serde_json::from_reader(&mut file).context("while reading JSON")
}
