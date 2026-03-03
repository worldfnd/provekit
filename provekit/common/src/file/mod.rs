mod bin;
mod buf_ext;
mod counting_writer;
mod json;

use {
    self::{
        bin::{read_bin, read_hash_config as read_hash_config_bin, write_bin, Compression},
        buf_ext::BufExt,
        counting_writer::CountingWriter,
        json::{read_json, write_json},
    },
    crate::{HashConfig, NoirProof, NoirProofScheme, Prover, Verifier},
    anyhow::Result,
    serde::{Deserialize, Serialize},
    std::{ffi::OsStr, path::Path},
    tracing::instrument,
};

/// Trait for structures that can be serialized to and deserialized from files.
pub trait FileFormat: Serialize + for<'a> Deserialize<'a> {
    const FORMAT: [u8; 8];
    const EXTENSION: &'static str;
    const VERSION: (u16, u16);
    const COMPRESSION: Compression;
}

/// Helper trait to optionally extract hash config.
pub(crate) trait MaybeHashAware {
    fn maybe_hash_config(&self) -> Option<HashConfig>;
}

/// Impl for Prover (has hash config).
impl MaybeHashAware for Prover {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        match self {
            Prover::Noir(p) => Some(p.hash_config),
            Prover::Mavros(p) => Some(p.hash_config),
        }
    }
}

/// Impl for Verifier (has hash config).
impl MaybeHashAware for Verifier {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        Some(self.hash_config)
    }
}

/// Impl for NoirProof (no hash config).
impl MaybeHashAware for NoirProof {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        None
    }
}

/// Impl for NoirProofScheme (has hash config).
impl MaybeHashAware for NoirProofScheme {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        match self {
            NoirProofScheme::Noir(d) => Some(d.hash_config),
            NoirProofScheme::Mavros(d) => Some(d.hash_config),
        }
    }
}

impl FileFormat for NoirProofScheme {
    const FORMAT: [u8; 8] = *b"NrProScm";
    const EXTENSION: &'static str = "nps";
    const VERSION: (u16, u16) = (1, 1);
    const COMPRESSION: Compression = Compression::Zstd;
}

impl FileFormat for Prover {
    const FORMAT: [u8; 8] = *b"PrvKitPr";
    const EXTENSION: &'static str = "pkp";
    const VERSION: (u16, u16) = (1, 1);
    const COMPRESSION: Compression = Compression::Xz;
}

impl FileFormat for Verifier {
    const FORMAT: [u8; 8] = *b"PrvKitVr";
    const EXTENSION: &'static str = "pkv";
    const VERSION: (u16, u16) = (1, 2);
    const COMPRESSION: Compression = Compression::Zstd;
}

impl FileFormat for NoirProof {
    const FORMAT: [u8; 8] = *b"NPSProof";
    const EXTENSION: &'static str = "np";
    const VERSION: (u16, u16) = (1, 0);
    const COMPRESSION: Compression = Compression::Zstd;
}

/// Write a file with format determined from extension.
#[allow(private_bounds)]
#[instrument(skip(value))]
pub fn write<T: FileFormat + MaybeHashAware>(value: &T, path: &Path) -> Result<()> {
    match path.extension().and_then(OsStr::to_str) {
        Some("json") => write_json(value, path),
        Some(ext) if ext == T::EXTENSION => {
            write_bin_with_hash_config(value, path, T::FORMAT, T::VERSION, T::COMPRESSION)
        }
        _ => Err(anyhow::anyhow!(
            "Unsupported file extension, please specify .{} or .json",
            T::EXTENSION
        )),
    }
}

/// Helper to write binary files with hash_config if T implements
/// MaybeHashAware.
fn write_bin_with_hash_config<T: FileFormat + MaybeHashAware>(
    value: &T,
    path: &Path,
    format: [u8; 8],
    version: (u16, u16),
    compression: Compression,
) -> Result<()> {
    let hash_config = value.maybe_hash_config();
    write_bin(value, path, format, version, compression, hash_config)
}

/// Read a file with format determined from extension.
#[instrument()]
pub fn read<T: FileFormat>(path: &Path) -> Result<T> {
    match path.extension().and_then(OsStr::to_str) {
        Some("json") => read_json(path),
        Some(ext) if ext == T::EXTENSION => read_bin(path, T::FORMAT, T::VERSION),
        _ => Err(anyhow::anyhow!(
            "Unsupported file extension, please specify .{} or .json",
            T::EXTENSION
        )),
    }
}

/// Read just the hash configuration from a file.
#[instrument()]
pub fn read_hash_config<T: FileFormat>(path: &Path) -> Result<HashConfig> {
    match path.extension().and_then(OsStr::to_str) {
        Some("json") => {
            // For JSON, parse and extract hash_config field (required)
            let json_str = std::fs::read_to_string(path)?;
            let value: serde_json::Value = serde_json::from_str(&json_str)?;
            value
                .get("hash_config")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .ok_or_else(|| anyhow::anyhow!("Missing hash_config field in JSON file"))
        }
        Some(ext) if ext == T::EXTENSION => read_hash_config_bin(path, T::FORMAT, T::VERSION),
        _ => Err(anyhow::anyhow!(
            "Unsupported file extension, please specify .{} or .json",
            T::EXTENSION
        )),
    }
}
