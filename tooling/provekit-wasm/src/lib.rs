//! WebAssembly bindings for ProveKit.
//!
//! This module provides browser-compatible WASM bindings for generating
//! zero-knowledge proofs using ProveKit. The API accepts binary (.pkp) or
//! JSON-encoded prover artifacts and TOML witness inputs, returning proofs
//! as JSON.
//!
//! # Example
//!
//! ```javascript
//! import { generateWitness } from '@noir-lang/noir_js';
//! import { initPanicHook, initThreadPool, Prover } from "./pkg/provekit_wasm.js";
//!
//! // Initialize panic hook and thread pool
//! initPanicHook();
//! await initThreadPool(navigator.hardwareConcurrency);
//!
//! // Load binary prover artifact (.pkp file)
//! const proverBin = new Uint8Array(await (await fetch("/prover.pkp")).arrayBuffer());
//! const prover = new Prover(proverBin);
//!
//! // Generate witness using Noir's JS library
//! const witnessStack = await generateWitness(compiledProgram, inputs);
//! const proof = await prover.proveBytes(witnessStack[witnessStack.length - 1].witness);
//! ```

// Re-export wasm-bindgen-rayon's thread pool initialization
pub use wasm_bindgen_rayon::init_thread_pool;
use {
    acir::{
        native_types::{Witness, WitnessMap},
        AcirField, FieldElement,
    },
    anyhow::Context,
    provekit_common::{NoirProof, Prover as ProverCore},
    provekit_prover::Prove,
    std::collections::BTreeMap,
    wasm_bindgen::prelude::*,
};

/// Magic bytes for ProveKit binary format
const MAGIC_BYTES: &[u8] = b"\xDC\xDFOZkp\x01\x00";
/// Format identifier for Prover files
const PROVER_FORMAT: &[u8; 8] = b"PrvKitPr";
/// Header size in bytes: MAGIC(8) + FORMAT(8) + MAJOR(2) + MINOR(2) + HASH_CONFIG(1) = 21
const HEADER_SIZE: usize = 21;

/// A prover instance for generating zero-knowledge proofs in WebAssembly.
///
/// This struct wraps a ProveKit prover and provides methods to generate proofs
/// from witness data. Create an instance using the JSON-encoded prover
/// artifact.
#[wasm_bindgen]
pub struct Prover {
    inner: ProverCore,
}

#[wasm_bindgen]
impl Prover {
    /// Creates a new prover from a ProveKit prover artifact.
    ///
    /// Accepts both binary (.pkp) and JSON formats. The format is auto-detected
    /// based on the file content:
    /// - Binary format: zstd-compressed postcard serialization with header
    /// - JSON format: standard JSON serialization
    ///
    /// # Arguments
    ///
    /// * `prover_data` - A byte slice containing the prover artifact (binary or
    ///   JSON)
    ///
    /// # Errors
    ///
    /// Returns an error if the data cannot be parsed as a valid prover
    /// artifact.
    #[wasm_bindgen(constructor)]
    pub fn new(prover_data: &[u8]) -> Result<Prover, JsError> {
        // Check if this is binary format by looking for magic bytes
        let is_binary = prover_data.len() >= HEADER_SIZE && &prover_data[..8] == MAGIC_BYTES;

        let inner = if is_binary {
            parse_binary_prover(prover_data)?
        } else {
            // Fall back to JSON - include first bytes for debugging
            let first_bytes: Vec<u8> = prover_data.iter().take(20).copied().collect();
            serde_json::from_slice(prover_data).map_err(|err| {
                JsError::new(&format!(
                    "Failed to parse prover JSON: {err}. Data length: {}, first 20 bytes: {:?}",
                    prover_data.len(),
                    first_bytes
                ))
            })?
        };
        Ok(Self { inner })
    }

    /// Generates a proof from a witness map and returns it as JSON bytes.
    ///
    /// Use this method after generating the witness using Noir's JavaScript
    /// library. The witness map should be a JavaScript Map or object
    /// mapping witness indices to hex-encoded field element strings.
    ///
    /// # Arguments
    ///
    /// * `witness_map` - JavaScript Map or object: `Map<number, string>` or `{
    ///   [index: number]: string }` where strings are hex-encoded field
    ///   elements
    ///
    /// # Returns
    ///
    /// A `Uint8Array` containing the JSON-encoded proof.
    ///
    /// # Errors
    ///
    /// Returns an error if the witness map cannot be parsed or proof generation
    /// fails.
    ///
    /// # Example
    ///
    /// ```javascript
    /// import { generateWitness } from '@noir-lang/noir_js';
    /// import { Prover } from './pkg/provekit_wasm.js';
    ///
    /// const witnessStack = await generateWitness(compiledProgram, inputs);
    /// const prover = new Prover(proverJson);
    /// // Use the witness from the last stack item
    /// const proof = await prover.proveBytes(witnessStack[witnessStack.length - 1].witness);
    /// ```
    #[wasm_bindgen(js_name = proveBytes)]
    pub fn prove_bytes(&self, witness_map: JsValue) -> Result<Box<[u8]>, JsError> {
        let witness = parse_witness_map(witness_map)?;
        let proof = generate_proof_from_witness(self.inner.clone(), witness)?;
        serde_json::to_vec(&proof)
            .map(|bytes| bytes.into_boxed_slice())
            .map_err(|err| JsError::new(&format!("Failed to serialize proof to JSON: {err}")))
    }

    /// Generates a proof from a witness map and returns it as a JavaScript
    /// object.
    ///
    /// Similar to [`proveBytes`](Self::prove_bytes), but returns the proof as a
    /// structured JavaScript object instead of JSON bytes.
    ///
    /// # Arguments
    ///
    /// * `witness_map` - JavaScript Map or object mapping witness indices to
    ///   hex-encoded field element strings
    ///
    /// # Errors
    ///
    /// Returns an error if the witness map cannot be parsed or proof generation
    /// fails.
    #[wasm_bindgen(js_name = proveJs)]
    pub fn prove_js(&self, witness_map: JsValue) -> Result<JsValue, JsError> {
        let witness = parse_witness_map(witness_map)?;
        let proof = generate_proof_from_witness(self.inner.clone(), witness)?;
        serde_wasm_bindgen::to_value(&proof)
            .map_err(|err| JsError::new(&format!("Failed to convert proof to JsValue: {err}")))
    }
}

/// Initializes panic hook for better browser console error messages.
/// Idempotent — safe to call multiple times.
#[wasm_bindgen(js_name = initPanicHook)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

// TODO: Re-enable Verifier once tokio/mio dependency issue is resolved for WASM.
// The verifier has transitive deps on tokio/mio that don't support WASM.

fn generate_proof_from_witness(
    prover: ProverCore,
    witness: WitnessMap<FieldElement>,
) -> Result<NoirProof, JsError> {
    prover
        .prove_with_witness(witness)
        .context("Failed to generate proof")
        .map_err(|err| JsError::new(&err.to_string()))
}

/// Parses a binary prover artifact (.pkp format).
///
/// Header: MAGIC(8) + FORMAT(8) + VERSION(4) + HASH_CONFIG(1), then XZ-compressed postcard data.
fn parse_binary_prover(data: &[u8]) -> Result<ProverCore, JsError> {
    if data.len() < HEADER_SIZE {
        return Err(JsError::new("Prover data too short for binary format"));
    }

    if &data[..8] != MAGIC_BYTES {
        return Err(JsError::new("Invalid magic bytes in prover data"));
    }

    if &data[8..16] != PROVER_FORMAT {
        return Err(JsError::new(
            "Invalid format identifier: expected Prover (.pkp) format",
        ));
}

    let compressed = &data[HEADER_SIZE..];
    let mut decompressed = Vec::new();
    lzma_rs::xz_decompress(&mut std::io::Cursor::new(compressed), &mut decompressed)
        .map_err(|err| JsError::new(&format!("Failed to decompress XZ prover data: {err}")))?;

    postcard::from_bytes(&decompressed)
        .map_err(|err| JsError::new(&format!("Failed to deserialize prover data: {err}")))
}

/// Parses a JavaScript witness map into the internal format.
///
/// The JavaScript witness map can be either:
/// 1. A Map<number, string> where strings are hex-encoded field elements
/// 2. A plain JavaScript object { [index: number]: string }
fn parse_witness_map(js_value: JsValue) -> Result<WitnessMap<FieldElement>, JsError> {
    // Try to deserialize as a BTreeMap with string keys (JS object keys are always
    // strings)
    let map: BTreeMap<String, String> =
        serde_wasm_bindgen::from_value(js_value).map_err(|err| {
            JsError::new(&format!(
                "Failed to parse witness map. Expected object mapping witness indices to hex \
                 strings: {err}"
            ))
        })?;

    if map.is_empty() {
        return Err(JsError::new("Witness map is empty"));
    }

    let mut witness_map = WitnessMap::new();

    for (index_str, hex_value) in map {
        let index: u32 = index_str.parse().map_err(|err| {
            JsError::new(&format!(
                "Failed to parse witness index '{index_str}': {err}"
            ))
        })?;

        let hex_str = hex_value.trim_start_matches("0x");

        let bytes = hex::decode(hex_str).map_err(|err| {
            JsError::new(&format!(
                "Failed to parse hex string at index {index}: {err}"
            ))
        })?;

        let field_element = FieldElement::from_be_bytes_reduce(&bytes);

        witness_map.insert(Witness(index), field_element);
    }

    Ok(witness_map)
}
