use {
    crate::format::parse_binary_prover,
    acir::{
        circuit::Program,
        native_types::{Witness, WitnessMap},
        AcirField, FieldElement,
    },
    anyhow::Context,
    base64::{engine::general_purpose::STANDARD as BASE64, Engine as _},
    provekit_backend_bn254::{Bn254Field, NoirElement, Prove, ProvekitProof, Prover as ProverCore},
    provekit_common::binary_format::{HEADER_SIZE, MAGIC_BYTES},
    std::{cell::RefCell, collections::BTreeMap},
    wasm_bindgen::prelude::*,
};
#[cfg(target_arch = "wasm32")]
use {
    ark_ff::PrimeField,
    js_sys::{Array, Function, Reflect, Uint8Array},
    noirc_abi::{AbiType, MAIN_RETURN_NAME},
    provekit_backend_bn254::{
        prove_mavros_with_wasm_driver, ConstraintsLayout, FieldElement as NativeFieldElement,
        MavrosPhase1Result, MavrosTableInfo, MavrosTableKind, MavrosWasmDriver, WitnessLayout,
    },
    serde::Deserialize,
    serde_json::Value,
};

#[cfg(target_arch = "wasm32")]
const MAVROS_BUFFER_ABI_VERSION: u32 = 2;

#[cfg(target_arch = "wasm32")]
const _: [(); MAX_FIELD_ELEMENT_BYTES] = [(); std::mem::size_of::<NativeFieldElement>()];

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

    /// Generates a proof for Mavros provers using browser-side Mavros WASM
    /// artifacts.
    ///
    /// `inputs` is the regular ABI-shaped input object. `runner` must expose:
    ///
    /// - `mavrosBufferAbiVersion = 2`
    /// - synchronous `runWitgenInto(...)` and `runAdInto(...)` methods
    ///
    /// Buffer ABI v2 uses 32-byte little-endian BN254 Montgomery-form field
    /// elements for all field buffers. The witgen multiplicity section is the
    /// only exception: each slot is a canonical `u64` in limb 0 and zero in
    /// limbs 1..3.
    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = proveMavrosBytes)]
    pub fn prove_mavros_bytes(
        &mut self,
        inputs: JsValue,
        runner: JsValue,
    ) -> Result<Box<[u8]>, JsError> {
        let proof = self.prove_mavros_inner(inputs, runner)?;
        serde_json::to_vec(&proof)
            .map(|bytes| bytes.into_boxed_slice())
            .map_err(|err| JsError::new(&format!("Failed to serialize proof to JSON: {err}")))
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = proveMavrosJs)]
    pub fn prove_mavros_js(
        &mut self,
        inputs: JsValue,
        runner: JsValue,
    ) -> Result<JsValue, JsError> {
        let proof = self.prove_mavros_inner(inputs, runner)?;
        serde_wasm_bindgen::to_value(&proof)
            .map_err(|err| JsError::new(&format!("Failed to convert proof to JsValue: {err}")))
    }

    #[wasm_bindgen(js_name = getProverKind)]
    pub fn get_prover_kind(&self) -> Result<String, JsError> {
        Ok(match self.inner_ref()? {
            ProverCore::Noir(_) => "noir",
            ProverCore::Mavros(_) => "mavros",
        }
        .to_owned())
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
            ProverCore::Mavros(_) => {
                return Err(JsError::new("Only Noir provers are supported in WASM"))
            }
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

#[cfg(target_arch = "wasm32")]
impl Prover {
    fn prove_mavros_inner(
        &mut self,
        inputs: JsValue,
        runner: JsValue,
    ) -> Result<ProvekitProof<Bn254Field>, JsError> {
        validate_runner_abi(&runner).map_err(|err| JsError::new(&format!("{err:#}")))?;
        runner_method(&runner, "runWitgenInto").map_err(|err| JsError::new(&format!("{err:#}")))?;
        runner_method(&runner, "runAdInto").map_err(|err| JsError::new(&format!("{err:#}")))?;

        let inner = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("Prover has been consumed by a previous prove() call"))?;
        let ProverCore::Mavros(p) = inner else {
            return Err(JsError::new("proveMavrosJs requires a Mavros prover"));
        };

        let input_fields = flatten_mavros_inputs(&p.abi, inputs)?;
        let mut driver = JsMavrosDriver { runner };
        prove_mavros_with_wasm_driver(p, input_fields, &mut driver)
            .context("Failed to generate Mavros proof")
            .map_err(|err| JsError::new(&format!("{err:#}")))
    }
}

#[cfg(target_arch = "wasm32")]
struct JsMavrosDriver {
    runner: JsValue,
}

#[cfg(target_arch = "wasm32")]
impl MavrosWasmDriver for JsMavrosDriver {
    fn run_witgen(
        &mut self,
        input_fields: &[NativeFieldElement],
        witness_layout: WitnessLayout,
        constraints_layout: ConstraintsLayout,
    ) -> anyhow::Result<MavrosPhase1Result> {
        validate_runner_abi(&self.runner)?;
        let method = runner_method(&self.runner, "runWitgenInto")?;
        let (witness_layout_value, constraints_layout_value) =
            layout_values(witness_layout, constraints_layout)?;

        let mut out_wit_pre_comm = zero_field_vec(witness_layout.pre_commitment_size());
        let mut out_wit_post_comm = zero_field_vec(witness_layout.post_commitment_size());
        let mut out_a = zero_field_vec(constraints_layout.size());
        let mut out_b = zero_field_vec(constraints_layout.size());
        let mut out_c = zero_field_vec(constraints_layout.size());

        let input_view = fields_to_js_array(input_fields)?;
        let out_wit_pre_comm_view = new_field_js_array(out_wit_pre_comm.len())?;
        let out_wit_post_comm_view = new_field_js_array(out_wit_post_comm.len())?;
        let out_a_view = new_field_js_array(out_a.len())?;
        let out_b_view = new_field_js_array(out_b.len())?;
        let out_c_view = new_field_js_array(out_c.len())?;

        let args = Array::new();
        args.push(input_view.as_ref());
        args.push(out_wit_pre_comm_view.as_ref());
        args.push(out_wit_post_comm_view.as_ref());
        args.push(out_a_view.as_ref());
        args.push(out_b_view.as_ref());
        args.push(out_c_view.as_ref());
        args.push(&witness_layout_value);
        args.push(&constraints_layout_value);
        let result = method
            .apply(&self.runner, &args)
            .map_err(|err| anyhow::anyhow!("Mavros runner threw: {:?}", err))?;

        copy_js_array_to_fields(
            &out_wit_pre_comm_view,
            &mut out_wit_pre_comm,
            "outWitPreComm",
        )?;
        copy_js_array_to_fields(
            &out_wit_post_comm_view,
            &mut out_wit_post_comm,
            "outWitPostComm",
        )?;
        copy_js_array_to_fields(&out_a_view, &mut out_a, "outA")?;
        copy_js_array_to_fields(&out_b_view, &mut out_b, "outB")?;
        copy_js_array_to_fields(&out_c_view, &mut out_c, "outC")?;

        let tables: Vec<JsTableInfo> = serde_wasm_bindgen::from_value(get_prop(&result, "tables")?)
            .map_err(|err| anyhow::anyhow!("failed to decode Mavros table metadata: {err}"))?;
        normalize_mavros_multiplicities(&mut out_wit_pre_comm, witness_layout)?;

        Ok(MavrosPhase1Result {
            out_wit_pre_comm,
            out_wit_post_comm,
            out_a,
            out_b,
            out_c,
            tables: tables
                .into_iter()
                .map(|table| {
                    Ok(MavrosTableInfo {
                        multiplicities_wit_offset: table.multiplicities_wit_offset,
                        num_indices: table.num_indices,
                        kind: MavrosTableKind::try_from(table.kind)?,
                        length: table.length,
                        elem_inverses_witness_section_offset: table
                            .elem_inverses_witness_section_offset,
                        elem_inverses_constraint_section_offset: table
                            .elem_inverses_constraint_section_offset,
                    })
                })
                .collect::<anyhow::Result<_>>()?,
        })
    }

    fn run_ad(
        &mut self,
        coeffs: &[NativeFieldElement],
        witness_layout: WitnessLayout,
        constraints_layout: ConstraintsLayout,
    ) -> anyhow::Result<[Vec<NativeFieldElement>; 3]> {
        validate_runner_abi(&self.runner)?;
        let method = runner_method(&self.runner, "runAdInto")?;
        let (witness_layout_value, constraints_layout_value) =
            layout_values(witness_layout, constraints_layout)?;

        let mut out_da = zero_field_vec(witness_layout.size());
        let mut out_db = zero_field_vec(witness_layout.size());
        let mut out_dc = zero_field_vec(witness_layout.size());

        let coeffs_view = fields_to_js_array(coeffs)?;
        let out_da_view = new_field_js_array(out_da.len())?;
        let out_db_view = new_field_js_array(out_db.len())?;
        let out_dc_view = new_field_js_array(out_dc.len())?;

        let args = Array::new();
        args.push(coeffs_view.as_ref());
        args.push(out_da_view.as_ref());
        args.push(out_db_view.as_ref());
        args.push(out_dc_view.as_ref());
        args.push(&witness_layout_value);
        args.push(&constraints_layout_value);
        method
            .apply(&self.runner, &args)
            .map_err(|err| anyhow::anyhow!("Mavros runner threw: {:?}", err))?;

        copy_js_array_to_fields(&out_da_view, &mut out_da, "outDa")?;
        copy_js_array_to_fields(&out_db_view, &mut out_db, "outDb")?;
        copy_js_array_to_fields(&out_dc_view, &mut out_dc, "outDc")?;

        Ok([out_da, out_db, out_dc])
    }
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsTableInfo {
    multiplicities_wit_offset: usize,
    num_indices: usize,
    kind: u32,
    length: usize,
    elem_inverses_witness_section_offset: usize,
    elem_inverses_constraint_section_offset: usize,
}

#[cfg(target_arch = "wasm32")]
fn runner_method(runner: &JsValue, method: &str) -> anyhow::Result<Function> {
    Reflect::get(runner, &JsValue::from_str(method))
        .map_err(|err| anyhow::anyhow!("Mavros runner method `{method}` lookup failed: {err:?}"))?
        .dyn_into::<Function>()
        .map_err(|err| {
            anyhow::anyhow!("Mavros runner method `{method}` is not a function: {err:?}")
        })
}

#[cfg(target_arch = "wasm32")]
fn layout_values(
    witness_layout: WitnessLayout,
    constraints_layout: ConstraintsLayout,
) -> anyhow::Result<(JsValue, JsValue)> {
    let witness_layout = serde_wasm_bindgen::to_value(&witness_layout)
        .map_err(|err| anyhow::anyhow!("failed to encode Mavros witness layout: {err}"))?;
    let constraints_layout = serde_wasm_bindgen::to_value(&constraints_layout)
        .map_err(|err| anyhow::anyhow!("failed to encode Mavros constraints layout: {err}"))?;
    Ok((witness_layout, constraints_layout))
}

#[cfg(target_arch = "wasm32")]
fn get_prop(value: &JsValue, name: &str) -> anyhow::Result<JsValue> {
    Reflect::get(value, &JsValue::from_str(name))
        .map_err(|err| anyhow::anyhow!("missing Mavros runner result property `{name}`: {err:?}"))
}

#[cfg(target_arch = "wasm32")]
fn validate_runner_abi(runner: &JsValue) -> anyhow::Result<()> {
    let version = Reflect::get(runner, &JsValue::from_str("mavrosBufferAbiVersion"))
        .map_err(|err| anyhow::anyhow!("missing Mavros runner buffer ABI version: {err:?}"))?
        .as_f64()
        .ok_or_else(|| anyhow::anyhow!("Mavros runner buffer ABI version must be a number"))?;
    anyhow::ensure!(
        version == f64::from(MAVROS_BUFFER_ABI_VERSION),
        "unsupported Mavros runner buffer ABI version {version}; expected \
         {MAVROS_BUFFER_ABI_VERSION}"
    );
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn zero_field_vec(len: usize) -> Vec<NativeFieldElement> {
    vec![NativeFieldElement::from(0u64); len]
}

#[cfg(target_arch = "wasm32")]
fn fields_to_js_array(fields: &[NativeFieldElement]) -> anyhow::Result<Uint8Array> {
    let len = checked_field_bytes(fields.len())?;
    let array = uint8_array_with_len(len)?;
    let bytes = unsafe {
        // SAFETY: `assert_field_byte_layout` guarantees each field occupies
        // exactly `MAX_FIELD_ELEMENT_BYTES`; this creates a temporary read-only
        // byte slice that is immediately copied into a JS-owned Uint8Array.
        std::slice::from_raw_parts(fields.as_ptr().cast::<u8>(), len)
    };
    array.copy_from(bytes);
    Ok(array)
}

#[cfg(target_arch = "wasm32")]
fn new_field_js_array(fields_len: usize) -> anyhow::Result<Uint8Array> {
    uint8_array_with_len(checked_field_bytes(fields_len)?)
}

#[cfg(target_arch = "wasm32")]
fn uint8_array_with_len(len: usize) -> anyhow::Result<Uint8Array> {
    let len = u32::try_from(len)
        .map_err(|_| anyhow::anyhow!("Mavros buffer is too large for Uint8Array"))?;
    Ok(Uint8Array::new_with_length(len))
}

#[cfg(target_arch = "wasm32")]
fn checked_field_bytes(fields_len: usize) -> anyhow::Result<usize> {
    fields_len
        .checked_mul(MAX_FIELD_ELEMENT_BYTES)
        .ok_or_else(|| anyhow::anyhow!("Mavros field buffer length overflow"))
}

#[cfg(target_arch = "wasm32")]
fn copy_js_array_to_fields(
    array: &Uint8Array,
    fields: &mut [NativeFieldElement],
    label: &str,
) -> anyhow::Result<()> {
    let expected_len = checked_field_bytes(fields.len())?;
    anyhow::ensure!(
        array.length() as usize == expected_len,
        "Mavros {label} buffer length {} does not match expected {expected_len}",
        array.length()
    );
    let bytes = unsafe {
        // SAFETY: `assert_field_byte_layout` guarantees the field slice is the
        // expected contiguous byte layout. The copy is from a JS-owned typed
        // array after the runner has returned, so no user JS runs while this
        // Rust-owned memory is exposed as bytes.
        std::slice::from_raw_parts_mut(fields.as_mut_ptr().cast::<u8>(), expected_len)
    };
    array.copy_to(bytes);
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn normalize_mavros_multiplicities(
    fields: &mut [NativeFieldElement],
    layout: WitnessLayout,
) -> anyhow::Result<()> {
    let start = layout.algebraic_size;
    let end = start + layout.multiplicities_size;
    for (offset, field) in fields[start..end].iter_mut().enumerate() {
        let limbs = field.0 .0;
        anyhow::ensure!(
            limbs[1..] == [0, 0, 0],
            "Mavros multiplicity slot {} must be canonical u64 in limb 0 with zero high limbs",
            start + offset
        );
        *field = NativeFieldElement::from(limbs[0]);
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn flatten_mavros_inputs(
    abi: &noirc_abi::Abi,
    inputs: JsValue,
) -> Result<Vec<NativeFieldElement>, JsError> {
    let value: Value = serde_wasm_bindgen::from_value(inputs)
        .map_err(|err| JsError::new(&format!("Failed to parse Mavros inputs: {err}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| JsError::new("Mavros inputs must be a plain object"))?;

    let mut fields = Vec::new();
    for param in &abi.parameters {
        let param_value = object
            .get(&param.name)
            .ok_or_else(|| JsError::new(&format!("Parameter '{}' not found", param.name)))?;
        flatten_abi_value(&param.typ, param_value, &param.name, &mut fields)?;
    }

    if let Some(return_type) = &abi.return_type {
        if let Some(return_value) = object.get(MAIN_RETURN_NAME) {
            flatten_abi_value(
                &return_type.abi_type,
                return_value,
                MAIN_RETURN_NAME,
                &mut fields,
            )?;
        }
    }

    Ok(fields)
}

#[cfg(target_arch = "wasm32")]
fn flatten_abi_value(
    abi_type: &AbiType,
    value: &Value,
    path: &str,
    out: &mut Vec<NativeFieldElement>,
) -> Result<(), JsError> {
    match abi_type {
        AbiType::Field | AbiType::Integer { .. } => {
            out.push(parse_json_field(value, path)?);
        }
        AbiType::Boolean => {
            let b = value
                .as_bool()
                .ok_or_else(|| JsError::new(&format!("{path} must be a boolean")))?;
            out.push(NativeFieldElement::from(u64::from(b)));
        }
        AbiType::Array { length, typ } => {
            let values = value
                .as_array()
                .ok_or_else(|| JsError::new(&format!("{path} must be an array")))?;
            if values.len() != *length as usize {
                return Err(JsError::new(&format!(
                    "{path} length {} does not match ABI length {}",
                    values.len(),
                    length
                )));
            }
            for (idx, item) in values.iter().enumerate() {
                flatten_abi_value(typ, item, &format!("{path}[{idx}]"), out)?;
            }
        }
        AbiType::Struct { fields, .. } => {
            let object = value
                .as_object()
                .ok_or_else(|| JsError::new(&format!("{path} must be an object")))?;
            for (field_name, field_type) in fields {
                let field_value = object.get(field_name).ok_or_else(|| {
                    JsError::new(&format!("{path}.{field_name} not found in struct input"))
                })?;
                flatten_abi_value(
                    field_type,
                    field_value,
                    &format!("{path}.{field_name}"),
                    out,
                )?;
            }
        }
        AbiType::Tuple { fields } => {
            let values = value
                .as_array()
                .ok_or_else(|| JsError::new(&format!("{path} must be a tuple array")))?;
            if values.len() != fields.len() {
                return Err(JsError::new(&format!(
                    "{path} length {} does not match tuple length {}",
                    values.len(),
                    fields.len()
                )));
            }
            for (idx, (field_type, item)) in fields.iter().zip(values).enumerate() {
                flatten_abi_value(field_type, item, &format!("{path}.{idx}"), out)?;
            }
        }
        AbiType::String { .. } => {
            return Err(JsError::new(
                "String inputs are not supported by the Mavros WASM path",
            ));
        }
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn parse_json_field(value: &Value, path: &str) -> Result<NativeFieldElement, JsError> {
    if let Some(n) = value.as_u64() {
        return Ok(NativeFieldElement::from(n));
    }
    if let Some(n) = value.as_i64() {
        if n >= 0 {
            return Ok(NativeFieldElement::from(n as u64));
        }
        return Ok(-NativeFieldElement::from(n.unsigned_abs()));
    }
    if let Some(s) = value.as_str() {
        let trimmed = s.trim();
        if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            let bytes = hex::decode(hex).map_err(|err| {
                JsError::new(&format!("Failed to parse hex string at {path}: {err}"))
            })?;
            if bytes.len() > MAX_FIELD_ELEMENT_BYTES {
                return Err(JsError::new(&format!(
                    "Hex value at {path} is {} bytes, exceeds BN254 field element size (32 bytes)",
                    bytes.len()
                )));
            }
            return Ok(NativeFieldElement::from_be_bytes_mod_order(&bytes));
        }
        return trimmed.parse::<NativeFieldElement>().map_err(|err| {
            JsError::new(&format!("Failed to parse decimal field at {path}: {err:?}"))
        });
    }

    Err(JsError::new(&format!(
        "{path} must be a number or a decimal/hex string"
    )))
}

impl Prover {
    fn inner_ref(&self) -> Result<&ProverCore, JsError> {
        self.inner
            .as_ref()
            .ok_or_else(|| JsError::new("Prover has been consumed by a previous prove() call"))
    }

    fn prove_inner(&mut self, witness_map: JsValue) -> Result<ProvekitProof<Bn254Field>, JsError> {
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
