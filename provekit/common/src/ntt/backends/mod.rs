pub mod cpu;

#[cfg(target_os = "macos")]
pub mod metal;

pub use cpu::RSFr;
#[cfg(target_os = "macos")]
pub use metal::MetalBn254Ntt;
