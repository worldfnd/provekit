//! WebAssembly bindings for ProveKit.
//!
//! This module provides browser-compatible WASM bindings for generating and
//! verifying zero-knowledge proofs using ProveKit. The API accepts `.wpkp`
//! (WASM ProveKit Prover) and `.wpkv` (WASM ProveKit Verifier) binary
//! artifacts — lightweight formats that strip fields unnecessary for the
//! browser (ACIR program, witness generator, ABI metadata).
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
//! // Load lightweight WASM prover artifact (.wpkp file)
//! const proverBin = new Uint8Array(await (await fetch("/prover.wpkp")).arrayBuffer());
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
    provekit_common::{NoirProof, WasmProver as WasmProverCore, WasmVerifier as WasmVerifierCore},
    provekit_prover::Prove,
    provekit_verifier::Verify,
    std::collections::BTreeMap,
    wasm_bindgen::prelude::*,
};

/// Magic bytes for ProveKit binary format
const MAGIC_BYTES: &[u8] = b"\xDC\xDFOZkp\x01\x00";
/// Format identifier for WASM Prover files (.wpkp)
const WASM_PROVER_FORMAT: &[u8; 8] = b"PrvKitWP";
/// Format identifier for WASM Verifier files (.wpkv)
const WASM_VERIFIER_FORMAT: &[u8; 8] = b"PrvKitWV";
/// Header size in bytes: MAGIC(8) + FORMAT(8) + MAJOR(2) + MINOR(2) +
/// HASH_CONFIG(1) = 21
const HEADER_SIZE: usize = 21;

/// A prover instance for generating zero-knowledge proofs in WebAssembly.
///
/// This struct wraps a lightweight ProveKit WASM prover and provides methods
/// to generate proofs from witness data. Create an instance by loading a
/// `.wpkp` artifact.
#[wasm_bindgen]
pub struct Prover {
    inner: WasmProverCore,
}

#[wasm_bindgen]
impl Prover {
    /// Creates a new prover from a `.wpkp` WASM prover artifact.
    ///
    /// Accepts binary `.wpkp` format (XZ-compressed postcard with header)
    /// or JSON serialization of a `WasmProver`.
    ///
    /// Generate `.wpkp` artifacts using:
    /// ```sh
    /// provekit-cli prepare circuit.json --pkp prover.pkp --pkv verifier.pkv --wasm
    /// # or convert an existing .pkp:
    /// provekit-cli convert-wasm prover.pkp
    /// ```
    ///
    /// # Arguments
    ///
    /// * `prover_data` - A byte slice containing the `.wpkp` artifact
    ///
    /// # Errors
    ///
    /// Returns an error if the data cannot be parsed as a valid WASM prover
    /// artifact.
    #[wasm_bindgen(constructor)]
    pub fn new(prover_data: &[u8]) -> Result<Prover, JsError> {
        let is_binary = prover_data.len() >= HEADER_SIZE && &prover_data[..8] == MAGIC_BYTES;

        let inner = if is_binary {
            parse_binary_wasm_prover(prover_data)?
        } else {
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
    #[wasm_bindgen(js_name = proveBytes)]
    pub fn prove_bytes(&self, witness_map: JsValue) -> Result<Box<[u8]>, JsError> {
        let witness = parse_witness_map(witness_map)?;
        let proof = self
            .inner
            .clone()
            .prove_with_witness(witness)
            .context("Failed to generate proof")
            .map_err(|err| JsError::new(&err.to_string()))?;
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
        let proof = self
            .inner
            .clone()
            .prove_with_witness(witness)
            .context("Failed to generate proof")
            .map_err(|err| JsError::new(&err.to_string()))?;
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

/// A verifier instance for verifying zero-knowledge proofs in WebAssembly.
///
/// This struct wraps a lightweight ProveKit WASM verifier. Create an instance
/// by loading a `.wpkv` artifact.
#[wasm_bindgen]
pub struct Verifier {
    inner: WasmVerifierCore,
}

#[wasm_bindgen]
impl Verifier {
    /// Creates a new verifier from a `.wpkv` WASM verifier artifact.
    ///
    /// Generate `.wpkv` artifacts using:
    /// ```sh
    /// provekit-cli prepare circuit.json --pkp prover.pkp --pkv verifier.pkv --wasm
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(verifier_data: &[u8]) -> Result<Verifier, JsError> {
        let is_binary =
            verifier_data.len() >= HEADER_SIZE && &verifier_data[..8] == MAGIC_BYTES;

        let inner = if is_binary {
            parse_binary_wasm_verifier(verifier_data)?
        } else {
            serde_json::from_slice(verifier_data).map_err(|err| {
                JsError::new(&format!("Failed to parse verifier JSON: {err}"))
            })?
        };
        Ok(Self { inner })
    }

    /// Verifies a proof provided as JSON bytes.
    ///
    /// # Arguments
    ///
    /// * `proof_json` - A `Uint8Array` containing JSON-encoded proof data
    ///
    /// # Errors
    ///
    /// Returns an error if the proof is invalid or verification fails.
    #[wasm_bindgen(js_name = verifyBytes)]
    pub fn verify_bytes(&mut self, proof_json: &[u8]) -> Result<(), JsError> {
        let proof: NoirProof = serde_json::from_slice(proof_json)
            .map_err(|err| JsError::new(&format!("Failed to parse proof JSON: {err}")))?;
        self.inner
            .verify(&proof)
            .map_err(|err| JsError::new(&err.to_string()))
    }

    /// Verifies a proof provided as a JavaScript object.
    #[wasm_bindgen(js_name = verifyJs)]
    pub fn verify_js(&mut self, proof: JsValue) -> Result<(), JsError> {
        let proof: NoirProof = serde_wasm_bindgen::from_value(proof)
            .map_err(|err| JsError::new(&format!("Failed to parse proof: {err}")))?;
        self.inner
            .verify(&proof)
            .map_err(|err| JsError::new(&err.to_string()))
    }
}

/// Parses a binary WASM prover artifact (.wpkp format).
///
/// Header: MAGIC(8) + FORMAT(8) + VERSION(4) + HASH_CONFIG(1), then
/// XZ-compressed postcard data.
fn parse_binary_wasm_prover(data: &[u8]) -> Result<WasmProverCore, JsError> {
    if data.len() < HEADER_SIZE {
        return Err(JsError::new("Prover data too short for binary format"));
    }

    if &data[..8] != MAGIC_BYTES {
        return Err(JsError::new("Invalid magic bytes in prover data"));
    }

    if &data[8..16] != WASM_PROVER_FORMAT {
        return Err(JsError::new(
            "Invalid format identifier: expected WASM Prover (.wpkp) format. Use `provekit-cli \
             convert-wasm` to convert a .pkp file.",
        ));
    }

    let compressed = &data[HEADER_SIZE..];
    let mut decompressed = Vec::new();
    lzma_rs::xz_decompress(&mut std::io::Cursor::new(compressed), &mut decompressed)
        .map_err(|err| JsError::new(&format!("Failed to decompress XZ prover data: {err}")))?;

    postcard::from_bytes(&decompressed)
        .map_err(|err| JsError::new(&format!("Failed to deserialize WASM prover data: {err}")))
}

/// Parses a binary WASM verifier artifact (.wpkv format).
///
/// Header: MAGIC(8) + FORMAT(8) + VERSION(4) + HASH_CONFIG(1), then
/// XZ-compressed postcard data.
fn parse_binary_wasm_verifier(data: &[u8]) -> Result<WasmVerifierCore, JsError> {
    if data.len() < HEADER_SIZE {
        return Err(JsError::new("Verifier data too short for binary format"));
    }

    if &data[..8] != MAGIC_BYTES {
        return Err(JsError::new("Invalid magic bytes in verifier data"));
    }

    if &data[8..16] != WASM_VERIFIER_FORMAT {
        return Err(JsError::new(
            "Invalid format identifier: expected WASM Verifier (.wpkv) format. Generate with \
             `provekit-cli prepare ... --wasm`.",
        ));
    }

    let compressed = &data[HEADER_SIZE..];
    let mut decompressed = Vec::new();
    lzma_rs::xz_decompress(&mut std::io::Cursor::new(compressed), &mut decompressed)
        .map_err(|err| JsError::new(&format!("Failed to decompress XZ verifier data: {err}")))?;

    postcard::from_bytes(&decompressed)
        .map_err(|err| JsError::new(&format!("Failed to deserialize WASM verifier data: {err}")))
}

/// Parses a JavaScript witness map into the internal format.
///
/// The JavaScript witness map can be either:
/// 1. A Map<number, string> where strings are hex-encoded field elements
/// 2. A plain JavaScript object { [index: number]: string }
fn parse_witness_map(js_value: JsValue) -> Result<WitnessMap<FieldElement>, JsError> {
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
