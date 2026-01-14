mod bin;
mod buf_ext;
mod counting_writer;
mod json;

use {
    self::{
        bin::{read_bin, read_hash_config as read_hash_config_bin, write_bin},
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
}

/// Trait for file formats that contain hash configuration.
pub trait HashAware {
    fn hash_config(&self) -> HashConfig;
}

/// Helper trait to optionally extract hash config.
pub(crate) trait MaybeHashAware {
    fn maybe_hash_config(&self) -> Option<HashConfig>;
}

/// Impl for Prover (has hash config).
impl<MerkleConfig, PowStrategy> MaybeHashAware for Prover<MerkleConfig, PowStrategy>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        Some(self.hash_config)
    }
}

/// Impl for Verifier (has hash config).
impl<MerkleConfig, PowStrategy> MaybeHashAware for Verifier<MerkleConfig, PowStrategy>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
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

/// Impl for NoirProofScheme (no hash config).
impl<MerkleConfig, PowStrategy> MaybeHashAware for NoirProofScheme<MerkleConfig, PowStrategy>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        None
    }
}

impl<MerkleConfig, PowStrategy> FileFormat for NoirProofScheme<MerkleConfig, PowStrategy>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
    NoirProofScheme<MerkleConfig, PowStrategy>: Serialize + for<'a> Deserialize<'a>,
{
    const FORMAT: [u8; 8] = *b"NrProScm";
    const EXTENSION: &'static str = "nps";
    const VERSION: (u16, u16) = (0, 1);
}

impl<MerkleConfig, PowStrategy> FileFormat for Prover<MerkleConfig, PowStrategy>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
    Prover<MerkleConfig, PowStrategy>: Serialize + for<'a> Deserialize<'a>,
{
    const FORMAT: [u8; 8] = *b"PrvKitPr";
    const EXTENSION: &'static str = "pkp";
    const VERSION: (u16, u16) = (0, 1);
}

impl<MerkleConfig, PowStrategy> HashAware for Prover<MerkleConfig, PowStrategy>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
    fn hash_config(&self) -> HashConfig {
        self.hash_config
    }
}

impl<MerkleConfig, PowStrategy> FileFormat for Verifier<MerkleConfig, PowStrategy>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
    Verifier<MerkleConfig, PowStrategy>: Serialize + for<'a> Deserialize<'a>,
{
    const FORMAT: [u8; 8] = *b"PrvKitVr";
    const EXTENSION: &'static str = "pkv";
    /// Version 0.1: Added hash_config byte at offset 20
    const VERSION: (u16, u16) = (0, 1);
}

impl<MerkleConfig, PowStrategy> HashAware for Verifier<MerkleConfig, PowStrategy>
where
    MerkleConfig: ark_crypto_primitives::merkle_tree::Config,
{
    fn hash_config(&self) -> HashConfig {
        self.hash_config
    }
}

impl FileFormat for NoirProof {
    const FORMAT: [u8; 8] = *b"NPSProof";
    const EXTENSION: &'static str = "np";
    /// Version 0.1: Added hash_config byte at offset 20
    const VERSION: (u16, u16) = (0, 1);
}

/// Write a file with format determined from extension.
#[allow(private_bounds)]
#[instrument(skip(value))]
pub fn write<T: FileFormat + MaybeHashAware>(value: &T, path: &Path) -> Result<()> {
    match path.extension().and_then(OsStr::to_str) {
        Some("json") => write_json(value, path),
        Some(ext) if ext == T::EXTENSION => {
            write_bin_with_hash_config(value, path, T::FORMAT, T::VERSION)
        }
        _ => Err(anyhow::anyhow!(
            "Unsupported file extension, please specify .{} or .json",
            T::EXTENSION
        )),
    }
}

/// Helper to write binary files with hash_config if T implements HashAware.
fn write_bin_with_hash_config<T: FileFormat + MaybeHashAware>(
    value: &T,
    path: &Path,
    format: [u8; 8],
    version: (u16, u16),
) -> Result<()> {
    let hash_config = value.maybe_hash_config();
    write_bin(value, path, format, version, hash_config)
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
