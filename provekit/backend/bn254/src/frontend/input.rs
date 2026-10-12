use {
    anyhow::{bail, ensure, Context, Result},
    mavros_artifacts::InputValueOrdered,
    mavros_vm::interpreter::flattened_param_count,
    noirc_abi::{
        input_parser::{Format, InputValue},
        Abi, AbiType, InputMap, MAIN_RETURN_NAME,
    },
    std::{fs, path::Path},
};

/// Parse a Noir prover input file (`Prover.toml` or `.json`) against `abi`.
pub fn read_prover_inputs(file_path: &Path, abi: &Abi) -> Result<InputMap> {
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();

    let Some(format) = Format::from_ext(ext) else {
        bail!("Unsupported input extension: {}", ext);
    };

    let inputs_src = fs::read_to_string(file_path)
        .with_context(|| format!("while reading inputs from {}", file_path.display()))?;
    format
        .parse(&inputs_src, abi)
        .with_context(|| format!("while parsing inputs from {}", file_path.display()))
}

/// Order parameters by ABI declaration, then append guard = 1 and the required
/// return.
pub fn ordered_mavros_inputs(abi: &Abi, input_map: &InputMap) -> Result<Vec<InputValueOrdered>> {
    let mut ordered_params = Vec::with_capacity(abi.parameters.len() + 2);
    for param in &abi.parameters {
        let param_value = input_map
            .get(&param.name)
            .ok_or_else(|| anyhow::anyhow!("inputs do not supply parameter `{}`", param.name))?;
        ordered_params.push(
            ordered_value(&param.typ, param_value)
                .with_context(|| format!("while ordering parameter `{}`", param.name))?,
        );
    }

    if let Some(return_type) = &abi.return_type {
        let return_value = input_map.get(MAIN_RETURN_NAME).ok_or_else(|| {
            anyhow::anyhow!(
                "the ABI declares a return value but the inputs do not supply `{MAIN_RETURN_NAME}`"
            )
        })?;
        ordered_params.push(InputValueOrdered::Field(1u64.into()));
        ordered_params.push(
            ordered_value(&return_type.abi_type, return_value)
                .with_context(|| format!("while ordering `{MAIN_RETURN_NAME}`"))?,
        );
    }

    let flattened = flattened_param_count(&ordered_params);
    let expected = abi.field_count() as usize
        + abi
            .return_type
            .as_ref()
            .map_or(0, |ret| 1 + ret.abi_type.field_count() as usize);
    ensure!(
        flattened == expected,
        "ordered inputs flatten to {flattened} field elements but the ABI declares {expected}"
    );
    Ok(ordered_params)
}

fn ordered_value(abi_type: &AbiType, value: &InputValue) -> Result<InputValueOrdered> {
    Ok(match (value, abi_type) {
        (InputValue::Field(elem), _) => InputValueOrdered::Field(super::noir_to_native(*elem)),
        (InputValue::Vec(vec_elements), AbiType::Array { typ, length }) => {
            ensure!(
                vec_elements.len() == *length as usize,
                "array value has {} elements but the ABI declares {length}",
                vec_elements.len()
            );
            InputValueOrdered::Vec(
                vec_elements
                    .iter()
                    .map(|elem| ordered_value(typ, elem))
                    .collect::<Result<Vec<_>>>()?,
            )
        }
        (InputValue::Struct(object), AbiType::Struct { fields, .. }) => InputValueOrdered::Struct(
            fields
                .iter()
                .map(|(field_name, field_type)| {
                    let field_value = object.get(field_name).ok_or_else(|| {
                        anyhow::anyhow!("field `{field_name}` not found in struct input")
                    })?;
                    Ok((field_name.clone(), ordered_value(field_type, field_value)?))
                })
                .collect::<Result<Vec<_>>>()?,
        ),
        (InputValue::String(string), AbiType::String { length }) => {
            let bytes = string.as_bytes();
            ensure!(
                bytes.len() == *length as usize,
                "string value has {} bytes but the ABI declares {length}",
                bytes.len()
            );
            InputValueOrdered::Vec(
                bytes
                    .iter()
                    .map(|byte| InputValueOrdered::Field(u64::from(*byte).into()))
                    .collect(),
            )
        }
        (InputValue::Vec(vec_elements), AbiType::Tuple { fields }) => {
            ensure!(
                vec_elements.len() == fields.len(),
                "tuple value has {} elements but the ABI declares {}",
                vec_elements.len(),
                fields.len()
            );
            InputValueOrdered::Struct(
                fields
                    .iter()
                    .zip(vec_elements)
                    .enumerate()
                    .map(|(idx, (field_type, field_value))| {
                        Ok((idx.to_string(), ordered_value(field_type, field_value)?))
                    })
                    .collect::<Result<Vec<_>>>()?,
            )
        }
        _ => bail!("input value does not match ABI type: {value:?} vs {abi_type:?}"),
    })
}
