mod bin;
mod buf_ext;
mod counting_writer;
mod json;

use {
    self::{
        bin::{read_bin, write_bin},
        buf_ext::BufExt,
        counting_writer::CountingWriter,
        json::{read_json, write_json},
    },
    crate::{noir_proof_scheme::NoirProof, NoirProofScheme},
    anyhow::Result,
    serde::{Deserialize, Serialize},
    std::{ffi::OsStr, path::PathBuf},
    tracing::instrument,
};

/// Trait for structures that can be serialized to and deserialized from files.
pub trait FileFormat: Serialize + for<'a> Deserialize<'a> {
    const FORMAT: [u8; 8];
    const EXTENSION: &'static str;
    const VERSION: (u16, u16);
}

impl FileFormat for NoirProofScheme {
    const FORMAT: [u8; 8] = *b"NrProScm";
    const EXTENSION: &'static str = "nps";
    const VERSION: (u16, u16) = (0, 0);
}

impl FileFormat for NoirProof {
    const FORMAT: [u8; 8] = *b"NPSProof";
    const EXTENSION: &'static str = "np";
    const VERSION: (u16, u16) = (0, 0);
}

/// Write a file with format determined from extension.
#[instrument(skip(value))]
pub fn write<T: FileFormat>(value: &T, path: &PathBuf) -> Result<()> {
    match path.extension().and_then(OsStr::to_str) {
        Some("json") => write_json(value, path),
        Some(ext) if ext == T::EXTENSION => write_bin(value, path, T::FORMAT, T::VERSION),
        _ => Err(anyhow::anyhow!(
            "Unsupported file extension, please specify .{} or .json",
            T::EXTENSION
        )),
    }
}

/// Read a file with format determined from extension.
#[instrument()]
pub fn read<T: FileFormat>(path: &PathBuf) -> Result<T> {
    match path.extension().and_then(OsStr::to_str) {
        Some("json") => read_json(path),
        Some(ext) if ext == T::EXTENSION => read_bin(path, T::FORMAT, T::VERSION),
        _ => Err(anyhow::anyhow!(
            "Unsupported file extension, please specify .{} or .json",
            T::EXTENSION
        )),
    }
}
