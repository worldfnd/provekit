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

// Re-export wasm-bindgen-rayon's thread pool initialization
pub use wasm_bindgen_rayon::init_thread_pool;
use {
    acir::{
        circuit::Program,
        native_types::{Witness, WitnessMap},
        AcirField, FieldElement,
    },
    anyhow::Context,
    base64::{engine::general_purpose::STANDARD as BASE64, Engine as _},
    provekit_common::{NoirElement, NoirProof, Prover as ProverCore, Verifier as VerifierCore},
    provekit_prover::Prove,
    provekit_verifier::Verify,
    std::collections::BTreeMap,
    wasm_bindgen::prelude::*,
};

/// Magic bytes for ProveKit binary format.
const MAGIC_BYTES: &[u8] = b"\xDC\xDFOZkp\x01\x00";
/// Format identifier for Prover files (.pkp).
const PROVER_FORMAT: &[u8; 8] = b"PrvKitPr";
/// Format identifier for Verifier files (.pkv).
const VERIFIER_FORMAT: &[u8; 8] = b"PrvKitVr";
/// Header size in bytes: MAGIC(8) + FORMAT(8) + MAJOR(2) + MINOR(2) +
/// HASH_CONFIG(1) = 21.
const HEADER_SIZE: usize = 21;

/// Expected version for Prover format (must match native `FileFormat for
/// Prover`).
const PROVER_VERSION: (u16, u16) = (1, 2);
/// Expected version for Verifier format (must match native `FileFormat for
/// Verifier`).
const VERIFIER_VERSION: (u16, u16) = (1, 3);

/// Zstd magic number for auto-detection.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
/// XZ magic number for auto-detection.
const XZ_MAGIC: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];

/// A prover instance for generating zero-knowledge proofs in WebAssembly.
///
/// Wraps the same `Prover` artifact used by the native CLI. Create an
/// instance by loading a `.pkp` file.
///
/// The prover is consumed after generating a proof — calling `proveBytes`
/// or `proveJs` a second time will return an error. Metadata methods
/// (`getCircuit`, `getNumConstraints`, `getNumWitnesses`) remain available
/// until the proof is generated.
#[wasm_bindgen]
pub struct Prover {
    inner: Option<ProverCore>,
}

#[wasm_bindgen]
impl Prover {
    /// Creates a new prover from a `.pkp` prover artifact.
    ///
    /// Accepts binary `.pkp` format (compressed postcard with header)
    /// or JSON serialization.
    ///
    /// Generate `.pkp` artifacts using:
    /// ```sh
    /// provekit-cli prepare circuit.json --pkp prover.pkp --pkv verifier.pkv
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(prover_data: &[u8]) -> Result<Prover, JsError> {
        let is_binary = prover_data.len() >= HEADER_SIZE && &prover_data[..8] == MAGIC_BYTES;

        let inner = if is_binary {
            parse_binary_prover(prover_data)?
        } else {
            serde_json::from_slice(prover_data).map_err(|err| {
                JsError::new(&format!(
                    "Failed to parse prover JSON: {err}. Data length: {}, first bytes: {:02X?}",
                    prover_data.len(),
                    &prover_data[..prover_data.len().min(20)]
                ))
            })?
        };
        Ok(Self { inner: Some(inner) })
    }

    /// Generates a proof from a witness map and returns it as JSON bytes.
    ///
    /// The witness map should be a JavaScript Map or object mapping witness
    /// indices to hex-encoded field element strings.
    ///
    /// The prover is consumed by this call — subsequent calls will error.
    #[wasm_bindgen(js_name = proveBytes)]
    pub fn prove_bytes(&mut self, witness_map: JsValue) -> Result<Box<[u8]>, JsError> {
        let proof = self.prove_inner(witness_map)?;
        serde_json::to_vec(&proof)
            .map(|bytes| bytes.into_boxed_slice())
            .map_err(|err| JsError::new(&format!("Failed to serialize proof to JSON: {err}")))
    }

    /// Generates a proof from a witness map and returns it as a JavaScript
    /// object.
    ///
    /// The prover is consumed by this call — subsequent calls will error.
    #[wasm_bindgen(js_name = proveJs)]
    pub fn prove_js(&mut self, witness_map: JsValue) -> Result<JsValue, JsError> {
        let proof = self.prove_inner(witness_map)?;
        serde_wasm_bindgen::to_value(&proof)
            .map_err(|err| JsError::new(&format!("Failed to convert proof to JsValue: {err}")))
    }

    /// Returns a circuit JSON suitable for `@noir-lang/noir_js`.
    ///
    /// Reconstructs `{ "abi": ..., "bytecode": "..." }` from the prover's
    /// embedded program and ABI so the browser can generate witnesses
    /// without a separate `circuit.json` file.
    ///
    /// ```js
    /// const prover = new Prover(pkpBytes);
    /// const circuitJson = JSON.parse(new TextDecoder().decode(prover.getCircuit()));
    /// const noir = new Noir(circuitJson);
    /// ```
    #[wasm_bindgen(js_name = getCircuit)]
    pub fn get_circuit(&self) -> Result<Box<[u8]>, JsError> {
        let noir_prover = match self.inner_ref()? {
            ProverCore::Noir(p) => p,
            #[allow(unreachable_patterns)]
            _ => return Err(JsError::new("Only Noir provers are supported in WASM")),
        };

        let program_bytes = Program::<NoirElement>::serialize_program(&noir_prover.program);
        let bytecode_b64 = BASE64.encode(&program_bytes);

        let abi_json = serde_json::to_value(&noir_prover.witness_generator.abi)
            .map_err(|e| JsError::new(&format!("Failed to serialize ABI: {e}")))?;

        let circuit = serde_json::json!({
            "abi": abi_json,
            "bytecode": bytecode_b64,
        });

        serde_json::to_vec(&circuit)
            .map(|b| b.into_boxed_slice())
            .map_err(|e| JsError::new(&format!("Failed to serialize circuit JSON: {e}")))
    }

    /// Returns the number of R1CS constraints in this circuit.
    #[wasm_bindgen(js_name = getNumConstraints)]
    pub fn get_num_constraints(&self) -> Result<usize, JsError> {
        Ok(self.inner_ref()?.size().0)
    }

    /// Returns the number of R1CS witnesses in this circuit.
    #[wasm_bindgen(js_name = getNumWitnesses)]
    pub fn get_num_witnesses(&self) -> Result<usize, JsError> {
        Ok(self.inner_ref()?.size().1)
    }
}

impl Prover {
    fn inner_ref(&self) -> Result<&ProverCore, JsError> {
        self.inner
            .as_ref()
            .ok_or_else(|| JsError::new("Prover has been consumed by a previous prove() call"))
    }

    fn prove_inner(&mut self, witness_map: JsValue) -> Result<NoirProof, JsError> {
        let witness = parse_witness_map(witness_map)?;
        let inner = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("Prover has been consumed by a previous prove() call"))?;
        inner
            .prove_with_witness(witness)
            .context("Failed to generate proof")
            .map_err(|err| JsError::new(&format!("{err:#}")))
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
/// Wraps the same `Verifier` artifact used by the native CLI. Create an
/// instance by loading a `.pkv` file.
#[wasm_bindgen]
pub struct Verifier {
    inner: VerifierCore,
}

#[wasm_bindgen]
impl Verifier {
    /// Creates a new verifier from a `.pkv` verifier artifact.
    ///
    /// Generate `.pkv` artifacts using:
    /// ```sh
    /// provekit-cli prepare circuit.json --pkp prover.pkp --pkv verifier.pkv
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(verifier_data: &[u8]) -> Result<Verifier, JsError> {
        let is_binary = verifier_data.len() >= HEADER_SIZE && &verifier_data[..8] == MAGIC_BYTES;

        let inner = if is_binary {
            parse_binary_verifier(verifier_data)?
        } else {
            serde_json::from_slice(verifier_data)
                .map_err(|err| JsError::new(&format!("Failed to parse verifier JSON: {err}")))?
        };
        Ok(Self { inner })
    }

    /// Verifies a proof provided as JSON bytes.
    #[wasm_bindgen(js_name = verifyBytes)]
    pub fn verify_bytes(&mut self, proof_json: &[u8]) -> Result<(), JsError> {
        let proof: NoirProof = serde_json::from_slice(proof_json)
            .map_err(|err| JsError::new(&format!("Failed to parse proof JSON: {err}")))?;
        self.inner
            .verify(&proof)
            .map_err(|err| JsError::new(&format!("{err:#}")))
    }

    /// Verifies a proof provided as a JavaScript object.
    #[wasm_bindgen(js_name = verifyJs)]
    pub fn verify_js(&mut self, proof: JsValue) -> Result<(), JsError> {
        let proof: NoirProof = serde_wasm_bindgen::from_value(proof)
            .map_err(|err| JsError::new(&format!("Failed to parse proof: {err}")))?;
        self.inner
            .verify(&proof)
            .map_err(|err| JsError::new(&format!("{err:#}")))
    }
}

// ---------------------------------------------------------------------------
// Binary format parsing
// ---------------------------------------------------------------------------

/// Validate a binary artifact header and return the payload after the header.
///
/// Checks magic bytes, format identifier, and version compatibility
/// (major must match exactly, minor must be >= expected minimum).
fn parse_binary_header<'a>(
    data: &'a [u8],
    expected_format: &[u8; 8],
    (expected_major, min_minor): (u16, u16),
    label: &str,
) -> Result<&'a [u8], JsError> {
    if data.len() < HEADER_SIZE {
        return Err(JsError::new(&format!(
            "{label} data too short for binary format"
        )));
    }
    if &data[..8] != MAGIC_BYTES {
        return Err(JsError::new(&format!(
            "Invalid magic bytes in {label} data"
        )));
    }
    if &data[8..16] != expected_format {
        return Err(JsError::new(&format!(
            "Invalid format identifier in {label} data"
        )));
    }

    let major = u16::from_le_bytes([data[16], data[17]]);
    let minor = u16::from_le_bytes([data[18], data[19]]);
    if major != expected_major {
        return Err(JsError::new(&format!(
            "Incompatible {label} format: major version {major}, expected {expected_major}"
        )));
    }
    if minor < min_minor {
        return Err(JsError::new(&format!(
            "Incompatible {label} format: minor version {minor}, expected >= {min_minor}"
        )));
    }

    Ok(&data[HEADER_SIZE..])
}

/// Auto-detect compression (Zstd or XZ) and decompress.
fn decompress(data: &[u8]) -> Result<Vec<u8>, JsError> {
    if data.len() >= 4 && data[..4] == ZSTD_MAGIC {
        let mut decoder = ruzstd::decoding::StreamingDecoder::new(std::io::Cursor::new(data))
            .map_err(|e| JsError::new(&format!("Failed to init Zstd decoder: {e}")))?;
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut out)
            .map_err(|e| JsError::new(&format!("Failed to decompress Zstd data: {e}")))?;
        Ok(out)
    } else if data.len() >= 6 && data[..6] == XZ_MAGIC {
        let mut out = Vec::new();
        lzma_rs::xz_decompress(&mut std::io::Cursor::new(data), &mut out)
            .map_err(|e| JsError::new(&format!("Failed to decompress XZ data: {e}")))?;
        Ok(out)
    } else {
        Err(JsError::new(&format!(
            "Unknown compression format (first bytes: {:02X?})",
            &data[..data.len().min(6)]
        )))
    }
}

/// Parses a binary prover artifact (.pkp format).
fn parse_binary_prover(data: &[u8]) -> Result<ProverCore, JsError> {
    let payload = parse_binary_header(data, PROVER_FORMAT, PROVER_VERSION, "prover")?;
    let decompressed = decompress(payload)?;
    postcard::from_bytes(&decompressed)
        .map_err(|err| JsError::new(&format!("Failed to deserialize prover data: {err}")))
}

/// Parses a binary verifier artifact (.pkv format).
fn parse_binary_verifier(data: &[u8]) -> Result<VerifierCore, JsError> {
    let payload = parse_binary_header(data, VERIFIER_FORMAT, VERIFIER_VERSION, "verifier")?;
    let decompressed = decompress(payload)?;
    postcard::from_bytes(&decompressed)
        .map_err(|err| JsError::new(&format!("Failed to deserialize verifier data: {err}")))
}

// ---------------------------------------------------------------------------
// Witness map parsing
// ---------------------------------------------------------------------------

/// Parses a JavaScript witness map into the internal format.
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
