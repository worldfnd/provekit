mod aarch64;
mod x86_64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::*;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("Only aarch64 and x86_64 are supported.");
