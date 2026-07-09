//! Noir/ACIR language bridge: witness generation, ABI display, input parsing,
//! and the Noir↔native field conversion.

mod abi;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod input;
mod native;
mod witness_generator;

pub use {abi::PrintAbi, native::noir_to_native, witness_generator::NoirWitnessGenerator};
