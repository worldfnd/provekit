pub mod binary_format;

/// Native-only file I/O (compression, serialization, deserialization).
/// Not available on WASM targets — use `binary_format` directly for format
/// constants.
#[cfg(not(target_arch = "wasm32"))]
mod io;

#[cfg(not(target_arch = "wasm32"))]
pub use io::*;
