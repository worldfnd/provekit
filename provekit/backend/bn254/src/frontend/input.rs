use {
    anyhow::{bail, ensure, Context, Result},
    mavros_artifacts::InputValueOrdered,
    noirc_abi::{
        input_parser::{Format, InputValue},
        Abi, AbiType, InputMap, MAIN_RETURN_NAME,
    },
    std::{fs, path::Path},
};

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

pub fn ordered_mavros_inputs(
    abi: &Abi,
    input_map: &InputMap,
) -> Result<(Vec<InputValueOrdered>, Option<Vec<crate::FieldElement>>)> {
    let mut params = Vec::with_capacity(abi.parameters.len());
    for param in &abi.parameters {
        let value = input_map
            .get(&param.name)
            .ok_or_else(|| anyhow::anyhow!("inputs do not supply parameter `{}`", param.name))?;
        params.push(
            ordered_value(&param.typ, value)
                .with_context(|| format!("while ordering parameter `{}`", param.name))?,
        );
    }
    let declared_return = match (&abi.return_type, input_map.get(MAIN_RETURN_NAME)) {
        (Some(return_type), Some(value)) => {
            let ordered = ordered_value(&return_type.abi_type, value)
                .with_context(|| format!("while ordering `{MAIN_RETURN_NAME}`"))?;
            Some(mavros_vm::interpreter::flatten_param_vec(&[ordered]))
        }
        _ => None,
    };
    Ok((params, declared_return))
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
        (InputValue::String(_), _) => bail!("string inputs are not supported for ordered params"),
        (InputValue::Vec(_), AbiType::Tuple { .. }) => {
            bail!("tuple inputs are not supported for ordered params")
        }
        _ => bail!("input value does not match ABI type: {value:?} vs {abi_type:?}"),
    })
}
