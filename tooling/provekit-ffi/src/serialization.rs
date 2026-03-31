//! Thin wrappers around `provekit_common::file::{serialize, deserialize}`
//! for in-memory byte serialization matching the binary file format.

use {
    anyhow::Result,
    provekit_common::file::FileFormat,
    serde::{Deserialize, Serialize},
};

pub(crate) fn serialize<T: FileFormat + Serialize>(value: &T) -> Result<Vec<u8>> {
    provekit_common::file::serialize(value)
}

pub(crate) fn deserialize<T: FileFormat + for<'a> Deserialize<'a>>(data: &[u8]) -> Result<T> {
    provekit_common::file::deserialize(data)
}
