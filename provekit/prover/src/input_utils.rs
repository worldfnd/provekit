use {
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
) -> Result<Vec<InputValueOrdered>, anyhow::Error> {
    let file_path = root.join("Prover.toml");
    let ext = file_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();

    let Some(format) = Format::from_ext(ext) else {
        return Err(anyhow::anyhow!("Unsupported input extension: {}", ext));
    };

    let inputs_src = fs::read_to_string(&file_path)?;
    let inputs = format.parse(&inputs_src, abi).unwrap();
    let ordered_params = ordered_params_from_btreemap(abi, &inputs);

    Ok(ordered_params)
}

pub fn ordered_params_from_btreemap(
    abi: &noirc_abi::Abi,
    unordered_params: &BTreeMap<String, InputValue>,
) -> Vec<InputValueOrdered> {
    let mut ordered_params = Vec::new();
    for param in &abi.parameters {
        let param_value = unordered_params
            .get(&param.name)
            .expect("Parameter not found in unordered params");

        ordered_params.push(ordered_param(&param.typ, param_value));
    }

    if let Some(return_type) = &abi.return_type {
        if let Some(return_value) = unordered_params.get(MAIN_RETURN_NAME) {
            ordered_params.push(ordered_param(&return_type.abi_type, return_value));
        }
    }

    ordered_params
}

fn ordered_param(abi_type: &AbiType, value: &InputValue) -> InputValueOrdered {
    match (value, abi_type) {
        (InputValue::Field(elem), _) => InputValueOrdered::Field(elem.into_repr()),

        (InputValue::Vec(vec_elements), AbiType::Array { typ, .. }) => InputValueOrdered::Vec(
            vec_elements
                .iter()
                .map(|elem| ordered_param(typ, elem))
                .collect(),
        ),
        (InputValue::Struct(object), AbiType::Struct { fields, .. }) => InputValueOrdered::Struct(
            fields
                .iter()
                .map(|(field_name, field_type)| {
                    let field_value = object.get(field_name).expect("Field not found in struct");
                    (field_name.clone(), ordered_param(field_type, field_value))
                })
                .collect::<Vec<_>>(),
        ),
        (InputValue::String(_string), _) => {
            panic!("Strings are not supported in ordered params");
        }

        (InputValue::Vec(_vec_elements), AbiType::Tuple { fields: _fields }) => {
            panic!("Tuples are not supported in ordered params");
        }
        _ => unreachable!("value should have already been checked to match abi type"),
    }
}
