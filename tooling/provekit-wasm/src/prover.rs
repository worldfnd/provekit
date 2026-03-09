use {
    crate::format::parse_binary_prover,
    acir::{
        circuit::Program,
        native_types::{Witness, WitnessMap},
        AcirField, FieldElement,
    },
    anyhow::Context,
    base64::{engine::general_purpose::STANDARD as BASE64, Engine as _},
    provekit_common::{
        binary_format::{HEADER_SIZE, MAGIC_BYTES},
        NoirElement, NoirProof, Prover as ProverCore,
    },
    provekit_prover::Prove,
    std::collections::BTreeMap,
    wasm_bindgen::prelude::*,
};

/// A prover instance for generating zero-knowledge proofs in WebAssembly.
///
/// Wraps the same `Prover` artifact used by the native CLI. Create an
/// instance by loading a `.pkp` file.
///
/// The prover is **consumed** by `proveBytes` / `proveJs` — calling either
/// a second time will return an error. Metadata methods (`getCircuit`,
/// `getNumConstraints`, `getNumWitnesses`) are available **before** proof
/// generation; once a proof is generated they will also error.
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

        // `from_be_bytes_reduce` reduces modulo the field order. This is safe
        // because noir_js always produces valid BN254 field elements as hex
        // strings — values are already in-range.
        let field_element = FieldElement::from_be_bytes_reduce(&bytes);

        witness_map.insert(Witness(index), field_element);
    }

    Ok(witness_map)
}
