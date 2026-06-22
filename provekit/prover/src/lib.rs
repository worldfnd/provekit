mod whir_r1cs;

#[cfg(not(target_arch = "wasm32"))]
pub use whir_r1cs::MavrosR1CSProver;
pub use whir_r1cs::WhirR1CSProver;
