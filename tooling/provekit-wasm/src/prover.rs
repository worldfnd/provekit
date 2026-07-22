use {
    crate::{
        error::{ErrorCode, WasmError, WasmResult},
        format::{ensure_json_artifact_size, looks_like_json, parse_binary_prover},
    },
    acir::{
        circuit::Program,
        native_types::{Witness, WitnessMap},
        AcirField, FieldElement,
    },
    anyhow::Context,
    base64::{engine::general_purpose::STANDARD as BASE64, Engine as _},
    provekit_backend_bn254::{Bn254Field, NoirElement, Prove, ProvekitProof, Prover as ProverCore},
    std::{
        cell::RefCell,
        collections::{BTreeMap, BTreeSet},
    },
    wasm_bindgen::prelude::*,
};

/// WASM bindings for proof generation. Consumed after `proveBytes`/`proveJs`.
///
/// JavaScript owners must call the generated `free()` method exactly once when
/// the handle is no longer needed. Calling `free()` releases native WASM state;
/// it does not zero copies of the artifact retained by JavaScript.
#[wasm_bindgen]
pub struct Prover {
    inner: Option<ProverCore>,
}

#[wasm_bindgen]
impl Prover {
    #[wasm_bindgen(constructor)]
    pub fn new(prover_data: &[u8]) -> Result<Prover, JsValue> {
        let inner = if looks_like_json(prover_data) {
            ensure_json_artifact_size(prover_data, "prover").map_err(WasmError::into_js_value)?;
            serde_json::from_slice(prover_data).map_err(|error| {
                WasmError::new(
                    ErrorCode::ArtifactJsonInvalid,
                    format!("Failed to parse prover JSON: {error}"),
                )
                .into_js_value()
            })?
        } else {
            parse_binary_prover(prover_data).map_err(WasmError::into_js_value)?
        };
        Ok(Self { inner: Some(inner) })
    }

    /// `witness_map`: JS `Map<number, string>` or plain object `{ "0": "0xhex…"
    /// }`.
    #[wasm_bindgen(js_name = proveBytes)]
    pub fn prove_bytes(&mut self, witness_map: JsValue) -> Result<Box<[u8]>, JsValue> {
        let proof = self
            .prove_inner(witness_map)
            .map_err(WasmError::into_js_value)?;
        serde_json::to_vec(&proof)
            .map(|bytes| bytes.into_boxed_slice())
            .map_err(|error| {
                WasmError::new(
                    ErrorCode::ProofSerializationFailed,
                    format!("Failed to serialize proof to JSON: {error}"),
                )
                .into_js_value()
            })
    }

    #[wasm_bindgen(js_name = proveJs)]
    pub fn prove_js(&mut self, witness_map: JsValue) -> Result<JsValue, JsValue> {
        let proof = self
            .prove_inner(witness_map)
            .map_err(WasmError::into_js_value)?;
        serde_wasm_bindgen::to_value(&proof).map_err(|error| {
            WasmError::new(
                ErrorCode::ProofSerializationFailed,
                format!("Failed to convert proof to JsValue: {error}"),
            )
            .into_js_value()
        })
    }

    /// Returns circuit JSON for `@noir-lang/noir_js`.
    ///
    /// ```js
    /// const prover = new Prover(pkpBytes);
    /// const circuitJson = JSON.parse(new TextDecoder().decode(prover.getCircuit()));
    /// const noir = new Noir(circuitJson);
    /// ```
    #[wasm_bindgen(js_name = getCircuit)]
    pub fn get_circuit(&self) -> Result<Box<[u8]>, JsValue> {
        let noir_prover = match self.inner_ref().map_err(WasmError::into_js_value)? {
            ProverCore::Noir(p) => p,
            ProverCore::Mavros(_) => {
                return Err(WasmError::new(
                    ErrorCode::UnsupportedProver,
                    "Only Noir provers are supported in WASM",
                )
                .into_js_value())
            }
        };

        let program_bytes = Program::<NoirElement>::serialize_program(&noir_prover.program);
        let bytecode_b64 = BASE64.encode(&program_bytes);

        let abi_json =
            serde_json::to_value(&noir_prover.witness_generator.abi).map_err(|error| {
                WasmError::new(
                    ErrorCode::ProofSerializationFailed,
                    format!("Failed to serialize ABI: {error}"),
                )
                .into_js_value()
            })?;

        let circuit = serde_json::json!({
            "abi": abi_json,
            "bytecode": bytecode_b64,
        });

        serde_json::to_vec(&circuit)
            .map(|b| b.into_boxed_slice())
            .map_err(|error| {
                WasmError::new(
                    ErrorCode::ProofSerializationFailed,
                    format!("Failed to serialize circuit JSON: {error}"),
                )
                .into_js_value()
            })
    }

    #[wasm_bindgen(js_name = getNumConstraints)]
    pub fn get_num_constraints(&self) -> Result<usize, JsValue> {
        Ok(self.inner_ref().map_err(WasmError::into_js_value)?.size().0)
    }

    #[wasm_bindgen(js_name = getNumWitnesses)]
    pub fn get_num_witnesses(&self) -> Result<usize, JsValue> {
        Ok(self.inner_ref().map_err(WasmError::into_js_value)?.size().1)
    }
}

impl Prover {
    fn inner_ref(&self) -> WasmResult<&ProverCore> {
        self.inner.as_ref().ok_or_else(|| {
            WasmError::new(
                ErrorCode::ProverConsumed,
                "Prover has been consumed by a previous prove() call",
            )
        })
    }

    fn prove_inner(&mut self, witness_map: JsValue) -> WasmResult<ProvekitProof<Bn254Field>> {
        let witness = parse_witness_map(witness_map)?;
        let inner = self.inner.take().ok_or_else(|| {
            WasmError::new(
                ErrorCode::ProverConsumed,
                "Prover has been consumed by a previous prove() call",
            )
        })?;
        inner
            .prove_with_witness(witness)
            .context("Failed to generate proof")
            .map_err(|error| WasmError::new(ErrorCode::ProvingFailed, format!("{error:#}")))
    }
}

/// Max byte length for a BN254 field element (32 bytes = 64 hex chars).
pub(crate) const MAX_FIELD_ELEMENT_BYTES: usize = 32;

/// Accepts a JS `Map<number|string, string>` or a plain object `{ "idx":
/// "0xhex…" }`.
pub(crate) fn parse_witness_map(js_value: JsValue) -> WasmResult<WitnessMap<FieldElement>> {
    let map: BTreeMap<String, String> = if js_value.is_instance_of::<js_sys::Map>() {
        js_map_to_btree(&js_sys::Map::from(js_value))?
    } else {
        serde_wasm_bindgen::from_value(js_value).map_err(|error| {
            WasmError::new(
                ErrorCode::WitnessInvalid,
                format!(
                    "Expected a Map or plain object mapping witness indices to hex strings: \
                     {error}"
                ),
            )
        })?
    };

    parse_witness_map_entries(map)
}

fn parse_witness_map_entries(
    map: BTreeMap<String, String>,
) -> WasmResult<WitnessMap<FieldElement>> {
    parse_witness_map_entries_impl(map)
}

fn parse_witness_map_entries_impl(
    map: BTreeMap<String, String>,
) -> WasmResult<WitnessMap<FieldElement>> {
    if map.is_empty() {
        return Err(WasmError::new(
            ErrorCode::WitnessInvalid,
            "Witness map is empty",
        ));
    }

    let mut witness_map = WitnessMap::new();
    let mut witness_indices = BTreeSet::new();

    for (index_str, hex_value) in map {
        let index: u32 = index_str.parse().map_err(|error| {
            WasmError::new(
                ErrorCode::WitnessInvalid,
                format!("Failed to parse witness index '{index_str}': {error}"),
            )
        })?;
        if !witness_indices.insert(index) {
            return Err(WasmError::new(
                ErrorCode::WitnessInvalid,
                format!("Duplicate witness index after normalization: {index}"),
            ));
        }

        let hex_str = hex_value.strip_prefix("0x").unwrap_or(&hex_value);
        if hex_str.is_empty() {
            return Err(WasmError::new(
                ErrorCode::WitnessInvalid,
                format!("Hex value at index {index} is empty"),
            ));
        }

        let bytes = hex::decode(hex_str).map_err(|error| {
            WasmError::new(
                ErrorCode::WitnessInvalid,
                format!("Failed to parse hex string at index {index}: {error}"),
            )
        })?;

        if bytes.len() > MAX_FIELD_ELEMENT_BYTES {
            return Err(WasmError::new(
                ErrorCode::WitnessInvalid,
                format!(
                    "Hex value at index {index} is {} bytes, exceeds BN254 field element size (32 \
                     bytes)",
                    bytes.len()
                ),
            ));
        }

        if !is_canonical_field_bytes(&bytes) {
            return Err(WasmError::new(
                ErrorCode::WitnessInvalid,
                format!("Hex value at index {index} is not a canonical BN254 field element"),
            ));
        }
        let field_element = FieldElement::from_be_bytes_reduce(&bytes);
        witness_map.insert(Witness(index), field_element);
    }

    Ok(witness_map)
}

fn is_canonical_field_bytes(bytes: &[u8]) -> bool {
    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    let value = &bytes[first_nonzero..];
    let modulus = FieldElement::modulus().to_bytes_be();
    value.len() < modulus.len() || (value.len() == modulus.len() && value < modulus.as_slice())
}

/// Converts a JS `Map` to `BTreeMap<String, String>`, handling numeric and
/// string keys and Witness objects with an `inner` property.
fn js_map_to_btree(map: &js_sys::Map) -> WasmResult<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    let err: RefCell<Option<String>> = RefCell::new(None);

    map.for_each(&mut |value: JsValue, key: JsValue| {
        if err.borrow().is_some() {
            return;
        }

        let key_str = if let Some(n) = key.as_f64() {
            match numeric_witness_index(n) {
                Ok(index) => index.to_string(),
                Err(message) => {
                    *err.borrow_mut() = Some(message);
                    return;
                }
            }
        } else if let Some(s) = key.as_string() {
            s
        } else if let Ok(inner) = js_sys::Reflect::get(&key, &"inner".into()) {
            if let Some(n) = inner.as_f64() {
                match numeric_witness_index(n) {
                    Ok(index) => index.to_string(),
                    Err(message) => {
                        *err.borrow_mut() = Some(message);
                        return;
                    }
                }
            } else {
                *err.borrow_mut() = Some("Map key has non-numeric .inner property".to_owned());
                return;
            }
        } else {
            *err.borrow_mut() = Some("Unsupported Map key type".to_owned());
            return;
        };

        let val_str = match value.as_string() {
            Some(s) => s,
            None => {
                *err.borrow_mut() = Some(format!("Map value at key {key_str} is not a string"));
                return;
            }
        };

        if result.insert(key_str.clone(), val_str).is_some() {
            *err.borrow_mut() = Some(format!(
                "Duplicate witness index after normalization: {key_str}"
            ));
        }
    });

    if let Some(msg) = err.into_inner() {
        return Err(WasmError::new(ErrorCode::WitnessInvalid, msg));
    }
    Ok(result)
}

fn numeric_witness_index(value: f64) -> Result<u32, String> {
    if !value.is_finite() || value.fract() != 0.0 || value < 0.0 || value > f64::from(u32::MAX) {
        return Err(format!(
            "Witness index must be an integer between 0 and {}",
            u32::MAX
        ));
    }
    Ok(value as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn witness_map_from_pairs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn max_field_element_bytes_is_32() {
        assert_eq!(MAX_FIELD_ELEMENT_BYTES, 32);
    }

    #[test]
    fn parse_witness_map_entries_parses_valid_hex_values() {
        let input = witness_map_from_pairs(&[("1", "0x01"), ("2", "ff")]);

        let parsed = parse_witness_map_entries(input).unwrap();

        assert_eq!(parsed.get(&Witness(1)), Some(&FieldElement::from(1_u128)));
        assert_eq!(parsed.get(&Witness(2)), Some(&FieldElement::from(255_u128)));
    }

    #[test]
    fn parse_witness_map_entries_rejects_empty_map() {
        let err = parse_witness_map_entries_impl(BTreeMap::new()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::WitnessInvalid);
        assert!(err.message().contains("Witness map is empty"));
    }

    #[test]
    fn parse_witness_map_entries_rejects_invalid_index() {
        let input = witness_map_from_pairs(&[("abc", "0x01")]);

        let err = parse_witness_map_entries_impl(input).unwrap_err();
        assert!(err
            .message()
            .contains("Failed to parse witness index 'abc'"));
    }

    #[test]
    fn parse_witness_map_entries_rejects_invalid_hex() {
        let input = witness_map_from_pairs(&[("1", "0xzz")]);

        let err = parse_witness_map_entries_impl(input).unwrap_err();
        assert!(err
            .message()
            .contains("Failed to parse hex string at index 1"));
    }

    #[test]
    fn parse_witness_map_entries_rejects_too_many_bytes() {
        let too_long_hex = format!("0x{}", "11".repeat(MAX_FIELD_ELEMENT_BYTES + 1));
        let mut input = BTreeMap::new();
        input.insert("5".to_owned(), too_long_hex);

        let err = parse_witness_map_entries_impl(input).unwrap_err();
        assert!(err
            .message()
            .contains("exceeds BN254 field element size (32 bytes)"));
    }

    #[test]
    fn parse_witness_map_entries_rejects_noncanonical_field_element() {
        let modulus = hex::encode(FieldElement::modulus().to_bytes_be());
        let input = witness_map_from_pairs(&[("1", &modulus)]);

        let err = parse_witness_map_entries_impl(input).unwrap_err();
        assert_eq!(err.code(), ErrorCode::WitnessInvalid);
        assert!(err
            .message()
            .contains("not a canonical BN254 field element"));
    }

    #[test]
    fn parse_witness_map_entries_rejects_duplicate_normalized_index() {
        let input = witness_map_from_pairs(&[("1", "0x01"), ("01", "0x02")]);

        let err = parse_witness_map_entries_impl(input).unwrap_err();
        assert_eq!(err.code(), ErrorCode::WitnessInvalid);
        assert!(err.message().contains("Duplicate witness index"));
    }

    #[test]
    fn numeric_witness_indices_must_be_exact_u32_values() {
        assert_eq!(numeric_witness_index(42.0), Ok(42));
        assert!(numeric_witness_index(-1.0).is_err());
        assert!(numeric_witness_index(1.5).is_err());
        assert!(numeric_witness_index(f64::NAN).is_err());
        assert!(numeric_witness_index(f64::from(u32::MAX) + 1.0).is_err());
    }
}
