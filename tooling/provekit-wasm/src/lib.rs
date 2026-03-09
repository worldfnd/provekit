//! WebAssembly bindings for ProveKit.
//!
//! This module provides browser-compatible WASM bindings for generating and
//! verifying zero-knowledge proofs using ProveKit. The API accepts the same
//! `.pkp` / `.pkv` binary artifacts used by the native CLI.
//!
//! # Example
//!
//! ```javascript
//! import { initPanicHook, initThreadPool, Prover } from "./pkg/provekit_wasm.js";
//!
//! // Initialize panic hook and thread pool
//! initPanicHook();
//! await initThreadPool(navigator.hardwareConcurrency);
//!
//! // Load prover artifact (.pkp file — same as native CLI uses)
//! const proverBin = new Uint8Array(await (await fetch("/prover.pkp")).arrayBuffer());
//! const prover = new Prover(proverBin);
//!
//! // Extract circuit for noir_js witness generation
//! const circuitJson = JSON.parse(new TextDecoder().decode(prover.getCircuit()));
//! const noir = new Noir(circuitJson);
//! const { witness } = await noir.execute(inputs);
//! const proof = prover.proveBytes(decompressWitness(witness)[0].witness);
//! ```

mod format;
mod prover;
mod verifier;

// Re-export wasm-bindgen-rayon's thread pool initialization
pub use wasm_bindgen_rayon::init_thread_pool;

/// Initializes panic hook for better browser console error messages.
/// Idempotent — safe to call multiple times.
#[wasm_bindgen::prelude::wasm_bindgen(js_name = initPanicHook)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}
