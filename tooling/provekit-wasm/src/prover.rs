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
    std::{cell::RefCell, collections::BTreeMap},
    wasm_bindgen::prelude::*,
};

/// WASM bindings for proof generation. Consumed after `proveBytes`/`proveJs`.
#[wasm_bindgen]
pub struct Prover {
    inner: Option<ProverCore>,
}

#[wasm_bindgen]
impl Prover {
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

    /// `witness_map`: JS `Map<number, string>` or plain object `{ "0": "0xhex…"
    /// }`.
    #[wasm_bindgen(js_name = proveBytes)]
    pub fn prove_bytes(&mut self, witness_map: JsValue) -> Result<Box<[u8]>, JsError> {
        let proof = self.prove_inner(witness_map)?;
        serde_json::to_vec(&proof)
            .map(|bytes| bytes.into_boxed_slice())
            .map_err(|err| JsError::new(&format!("Failed to serialize proof to JSON: {err}")))
    }

    #[wasm_bindgen(js_name = proveJs)]
    pub fn prove_js(&mut self, witness_map: JsValue) -> Result<JsValue, JsError> {
        let proof = self.prove_inner(witness_map)?;
        serde_wasm_bindgen::to_value(&proof)
            .map_err(|err| JsError::new(&format!("Failed to convert proof to JsValue: {err}")))
    }

    /// Returns circuit JSON for `@noir-lang/noir_js`.
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

    #[wasm_bindgen(js_name = getNumConstraints)]
    pub fn get_num_constraints(&self) -> Result<usize, JsError> {
        Ok(self.inner_ref()?.size().0)
    }

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

/// Max byte length for a BN254 field element (32 bytes = 64 hex chars).
pub(crate) const MAX_FIELD_ELEMENT_BYTES: usize = 32;

/// Accepts a JS `Map<number|string, string>` or a plain object `{ "idx":
/// "0xhex…" }`.
pub(crate) fn parse_witness_map(js_value: JsValue) -> Result<WitnessMap<FieldElement>, JsError> {
    let map: BTreeMap<String, String> = if js_value.is_instance_of::<js_sys::Map>() {
        js_map_to_btree(&js_sys::Map::from(js_value))?
    } else {
        serde_wasm_bindgen::from_value(js_value).map_err(|err| {
            JsError::new(&format!(
                "Expected a Map or plain object mapping witness indices to hex strings: {err}"
            ))
        })?
    };

    parse_witness_map_entries(map)
}

fn parse_witness_map_entries(
    map: BTreeMap<String, String>,
) -> Result<WitnessMap<FieldElement>, JsError> {
    parse_witness_map_entries_impl(map).map_err(|msg| JsError::new(&msg))
}

fn parse_witness_map_entries_impl(
    map: BTreeMap<String, String>,
) -> Result<WitnessMap<FieldElement>, String> {
    if map.is_empty() {
        return Err("Witness map is empty".to_owned());
    }

    let mut witness_map = WitnessMap::new();

    for (index_str, hex_value) in map {
        let index: u32 = index_str
            .parse()
            .map_err(|err| format!("Failed to parse witness index '{index_str}': {err}"))?;

        let hex_str = hex_value.trim_start_matches("0x");

        let bytes = hex::decode(hex_str)
            .map_err(|err| format!("Failed to parse hex string at index {index}: {err}"))?;

        if bytes.len() > MAX_FIELD_ELEMENT_BYTES {
            return Err(format!(
                "Hex value at index {index} is {} bytes, exceeds BN254 field element size (32 \
                 bytes)",
                bytes.len()
            ));
        }

        let field_element = FieldElement::from_be_bytes_reduce(&bytes);
        witness_map.insert(Witness(index), field_element);
    }

    Ok(witness_map)
}

/// Converts a JS `Map` to `BTreeMap<String, String>`, handling numeric and
/// string keys and Witness objects with an `inner` property.
fn js_map_to_btree(map: &js_sys::Map) -> Result<BTreeMap<String, String>, JsError> {
    let mut result = BTreeMap::new();
    let err: RefCell<Option<String>> = RefCell::new(None);

    map.for_each(&mut |value: JsValue, key: JsValue| {
        if err.borrow().is_some() {
            return;
        }

        let key_str = if let Some(n) = key.as_f64() {
            (n as u32).to_string()
        } else if let Some(s) = key.as_string() {
            s
        } else if let Ok(inner) = js_sys::Reflect::get(&key, &"inner".into()) {
            if let Some(n) = inner.as_f64() {
                (n as u32).to_string()
            } else {
                *err.borrow_mut() = Some(format!("Map key has non-numeric .inner property"));
                return;
            }
        } else {
            *err.borrow_mut() = Some(format!("Unsupported Map key type"));
            return;
        };

        let val_str = match value.as_string() {
            Some(s) => s,
            None => {
                *err.borrow_mut() = Some(format!("Map value at key {key_str} is not a string"));
                return;
            }
        };

        result.insert(key_str, val_str);
    });

    if let Some(msg) = err.into_inner() {
        return Err(JsError::new(&msg));
    }
    Ok(result)
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
        assert!(err.contains("Witness map is empty"));
    }

    #[test]
    fn parse_witness_map_entries_rejects_invalid_index() {
        let input = witness_map_from_pairs(&[("abc", "0x01")]);

        let err = parse_witness_map_entries_impl(input).unwrap_err();
        assert!(err.contains("Failed to parse witness index 'abc'"));
    }

    #[test]
    fn parse_witness_map_entries_rejects_invalid_hex() {
        let input = witness_map_from_pairs(&[("1", "0xzz")]);

        let err = parse_witness_map_entries_impl(input).unwrap_err();
        assert!(err.contains("Failed to parse hex string at index 1"));
    }

    #[test]
    fn parse_witness_map_entries_rejects_too_many_bytes() {
        let too_long_hex = format!("0x{}", "11".repeat(MAX_FIELD_ELEMENT_BYTES + 1));
        let mut input = BTreeMap::new();
        input.insert("5".to_owned(), too_long_hex);

        let err = parse_witness_map_entries_impl(input).unwrap_err();
        assert!(err.contains("exceeds BN254 field element size (32 bytes)"));
    }
}
