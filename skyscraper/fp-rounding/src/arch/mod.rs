mod aarch64;
mod wasm32;
mod x86_64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::*;
#[cfg(target_arch = "wasm32")]
pub use wasm32::*;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "x86_64",
    target_arch = "wasm32"
)))]
compile_error!("Only aarch64, x86_64, and wasm32 are supported.");
