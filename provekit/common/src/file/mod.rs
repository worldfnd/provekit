pub mod binary_format;

#[cfg(not(target_arch = "wasm32"))]
mod io;

#[cfg(not(target_arch = "wasm32"))]
pub use io::*;
