mod bin;
mod buf_ext;
mod counting_writer;
mod json;

pub use self::bin::Compression;
use {
    self::{
        bin::{
            deserialize_from_bytes, read_bin, read_hash_config as read_hash_config_bin,
            serialize_to_bytes, write_bin,
        },
        buf_ext::BufExt,
        counting_writer::CountingWriter,
        json::{read_json, write_json},
    },
    crate::HashConfig,
    anyhow::Result,
    serde::{Deserialize, Serialize},
    std::{ffi::OsStr, path::Path},
    tracing::{instrument, warn},
};

/// Trait for structures that can be serialized to and deserialized from files.
pub trait FileFormat: Serialize + for<'a> Deserialize<'a> {
    const FORMAT: [u8; 8];
    const EXTENSION: &'static str;
    const VERSION: (u16, u16);
    const COMPRESSION: Compression;
}

/// Helper trait to optionally extract hash config. Implemented for the concrete
/// scheme types in their owning crate (e.g. `provekit-backend-bn254`).
pub trait MaybeHashAware {
    fn maybe_hash_config(&self) -> Option<HashConfig>;
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
        Some("json") => {
            warn!(
                "Reading a JSON artifact. JSON files carry no header, so the format, version, and \
                 proof-field checks that the binary `.{ext}` format performs are all skipped \
                 here. A file written by an incompatible ProveKit version, or for a different \
                 proof field, is not rejected up front; it fails later during verification with \
                 an error that does not name the real cause.",
                ext = T::EXTENSION
            );
            read_json(path)
        }
        Some(ext) if ext == T::EXTENSION => read_bin(path, T::FORMAT, T::VERSION),
        _ => Err(anyhow::anyhow!(
            "Unsupported file extension, please specify .{} or .json",
            T::EXTENSION
        )),
    }
}

/// Serialize a value to bytes in the same binary format as `write`.
///
/// The output is byte-for-byte identical to what `write` produces on disk
/// (header + compressed postcard). Use `deserialize` to recover the value.
#[allow(private_bounds)]
pub fn serialize<T: FileFormat + MaybeHashAware>(value: &T) -> Result<Vec<u8>> {
    let hash_config = value.maybe_hash_config();
    serialize_to_bytes(value, T::FORMAT, T::VERSION, T::COMPRESSION, hash_config)
}

/// Deserialize a value from bytes produced by `serialize` or read from a file
/// written by `write`.
pub fn deserialize<T: FileFormat>(data: &[u8]) -> Result<T> {
    deserialize_from_bytes(data, T::FORMAT, T::VERSION)
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
