#[cfg(not(target_arch = "wasm32"))]
mod bin;
mod buf_ext;
#[cfg(not(target_arch = "wasm32"))]
mod counting_writer;
mod json;

use {
    self::{buf_ext::BufExt, json::{read_json, write_json}},
    crate::{NoirProof, NoirProofScheme, Prover, Verifier},
    anyhow::Result,
    serde::{Deserialize, Serialize},
    std::{ffi::OsStr, path::Path},
    tracing::instrument,
};

#[cfg(not(target_arch = "wasm32"))]
use self::{bin::{read_bin, write_bin}, counting_writer::CountingWriter};

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

impl FileFormat for Prover {
    const FORMAT: [u8; 8] = *b"PrvKitPr";
    const EXTENSION: &'static str = "pkp";
    const VERSION: (u16, u16) = (0, 0);
}

impl FileFormat for Verifier {
    const FORMAT: [u8; 8] = *b"PrvKitVr";
    const EXTENSION: &'static str = "pkv";
    const VERSION: (u16, u16) = (0, 0);
}

impl FileFormat for NoirProof {
    const FORMAT: [u8; 8] = *b"NPSProof";
    const EXTENSION: &'static str = "np";
    const VERSION: (u16, u16) = (0, 0);
}

/// Write a file with format determined from extension.
#[instrument(skip(value))]
pub fn write<T: FileFormat>(value: &T, path: &Path) -> Result<()> {
    match path.extension().and_then(OsStr::to_str) {
        Some("json") => write_json(value, path),
        #[cfg(not(target_arch = "wasm32"))]
        Some(ext) if ext == T::EXTENSION => write_bin(value, path, T::FORMAT, T::VERSION),
        _ => Err(anyhow::anyhow!(
            "Unsupported file extension, please specify .{} or .json",
            T::EXTENSION
        )),
    }
}

/// Read a file with format determined from extension.
#[instrument()]
pub fn read<T: FileFormat>(path: &Path) -> Result<T> {
    match path.extension().and_then(OsStr::to_str) {
        Some("json") => read_json(path),
        #[cfg(not(target_arch = "wasm32"))]
        Some(ext) if ext == T::EXTENSION => read_bin(path, T::FORMAT, T::VERSION),
        _ => Err(anyhow::anyhow!(
            "Unsupported file extension, please specify .{} or .json",
            T::EXTENSION
        )),
    }
}
