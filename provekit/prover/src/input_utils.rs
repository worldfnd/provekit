use {
    anyhow::{Context, Result},
    mavros_artifacts::InputValueOrdered,
    noirc_abi::{
        input_parser::{Format, InputValue},
        AbiType, MAIN_RETURN_NAME,
    },
    std::{collections::BTreeMap, fs, path::Path},
};

pub fn read_prover_inputs(
    root: &Path,
    abi: &noirc_abi::Abi,
) -> Result<BTreeMap<String, InputValue>, anyhow::Error> {
    let file_path = root.join("Prover.toml");
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();

    let Some(format) = Format::from_ext(ext) else {
        anyhow::bail!("Unsupported input extension: {}", ext);
    };

    let inputs_src = fs::read_to_string(&file_path)?;
    let inputs: BTreeMap<String, InputValue> = format
        .parse(&inputs_src, abi)
        .context("while parsing Prover.toml inputs")?;

    Ok(inputs)
}

pub fn ordered_params_from_btreemap(
    abi: &noirc_abi::Abi,
    unordered_params: &BTreeMap<String, InputValue>,
) -> Result<Vec<InputValueOrdered>> {
    let mut ordered_params = Vec::new();
    for param in &abi.parameters {
        let param_value = unordered_params
            .get(&param.name)
            .ok_or_else(|| anyhow::anyhow!("Parameter '{}' not found in inputs", param.name))?;

        ordered_params.push(ordered_param(&param.typ, param_value)?);
    }

    if let Some(return_type) = &abi.return_type {
        if let Some(return_value) = unordered_params.get(MAIN_RETURN_NAME) {
            ordered_params.push(ordered_param(&return_type.abi_type, return_value)?);
        }
    }

    Ok(ordered_params)
}

fn ordered_param(abi_type: &AbiType, value: &InputValue) -> Result<InputValueOrdered> {
    match (value, abi_type) {
        (InputValue::Field(elem), _) => Ok(InputValueOrdered::Field(elem.into_repr())),

        (InputValue::Vec(vec_elements), AbiType::Array { typ, .. }) => {
            let items = vec_elements
                .iter()
                .map(|elem| ordered_param(typ, elem))
                .collect::<Result<Vec<_>>>()?;
            Ok(InputValueOrdered::Vec(items))
        }
        (InputValue::Struct(object), AbiType::Struct { fields, .. }) => {
            let items = fields
                .iter()
                .map(|(field_name, field_type)| {
                    let field_value = object.get(field_name).ok_or_else(|| {
                        anyhow::anyhow!("Field '{}' not found in struct input", field_name)
                    })?;
                    Ok((field_name.clone(), ordered_param(field_type, field_value)?))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(InputValueOrdered::Struct(items))
        }
        (InputValue::String(_), _) => {
            anyhow::bail!("String inputs are not supported for ordered params")
        }
        (InputValue::Vec(_), AbiType::Tuple { .. }) => {
            anyhow::bail!("Tuple inputs are not supported for ordered params")
        }
        _ => anyhow::bail!(
            "Input value does not match ABI type: {:?} vs {:?}",
            value,
            abi_type
        ),
    }
}
