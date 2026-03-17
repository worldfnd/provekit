//! WebAssembly bindings for ProveKit.
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

pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen::prelude::wasm_bindgen(js_name = initPanicHook)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}
