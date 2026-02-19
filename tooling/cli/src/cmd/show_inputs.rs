use {
    super::Command,
    anyhow::{ensure, Context, Result},
    argh::FromArgs,
    ark_ff::{BigInteger, PrimeField},
    noirc_abi::{AbiType, AbiVisibility, Sign},
    provekit_common::{file::read, FieldElement, NoirProof, Verifier},
    std::path::PathBuf,
    tracing::instrument,
};

/// Display public inputs from a proof with their original variable names.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "show-inputs")]
pub struct Args {
    /// path to the verifier PKV file
    #[argh(positional)]
    verifier_path: PathBuf,

    /// path to the proof file
    #[argh(positional)]
    proof_path: PathBuf,

    /// display values in hexadecimal format
    #[argh(switch, long = "hex")]
    hex: bool,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let verifier: Verifier =
            read(&self.verifier_path).context("while reading Provekit Verifier")?;

        let proof: NoirProof = read(&self.proof_path).context("while reading proof")?;

        let abi = &verifier.abi;
        let values = &proof.public_inputs.0;

        println!("Public Inputs:");
        println!("==============");

        let mut idx = 0;

        for param in &abi.parameters {
            if !param.is_public() {
                continue;
            }
            let field_count = param.typ.field_count() as usize;
            ensure!(
                idx + field_count <= values.len(),
                "ABI expects more public inputs than the proof contains (need index {}, proof has \
                 {})",
                idx + field_count - 1,
                values.len()
            );
            idx = print_typed_value(&param.name, &param.typ, values, idx, 1, self.hex);
        }

        if let Some(ret) = &abi.return_type {
            if matches!(ret.visibility, AbiVisibility::Public) {
                let field_count = ret.abi_type.field_count() as usize;
                ensure!(
                    idx + field_count <= values.len(),
                    "ABI expects more public inputs than the proof contains (need index {}, proof \
                     has {})",
                    idx + field_count - 1,
                    values.len()
                );
                print_typed_value("return", &ret.abi_type, values, idx, 1, self.hex);
            }
        }

        Ok(())
    }
}

fn format_type(typ: &AbiType) -> String {
    match typ {
        AbiType::Field => "Field".to_string(),
        AbiType::Boolean => "bool".to_string(),
        AbiType::Integer { sign, width } => match sign {
            Sign::Signed => format!("i{}", width),
            Sign::Unsigned => format!("u{}", width),
        },
        AbiType::String { length } => format!("str<{}>", length),
        AbiType::Array { length, typ } => format!("[{}; {}]", format_type(typ), length),
        AbiType::Tuple { fields } => {
            let field_types: Vec<_> = fields.iter().map(format_type).collect();
            format!("({})", field_types.join(", "))
        }
        AbiType::Struct { path, .. } => path.to_string(),
    }
}

fn print_typed_value(
    name: &str,
    typ: &AbiType,
    values: &[FieldElement],
    idx: usize,
    indent: usize,
    hex: bool,
) -> usize {
    let indent_str = "  ".repeat(indent);

    match typ {
        AbiType::Field => {
            print!("{}{}: ", indent_str, name);
            print_field_value(&values[idx], hex);
            println!();
            idx + 1
        }
        AbiType::Boolean => {
            let val = values[idx].into_bigint();
            let bool_val = !val.is_zero();
            println!("{}{}: {}", indent_str, name, bool_val);
            idx + 1
        }
        AbiType::Integer { sign, width } => {
            print!("{}{} ({}): ", indent_str, name, format_type(typ));
            let val = values[idx].into_bigint();
            if matches!(sign, Sign::Signed) && *width <= 64 {
                let bytes = val.to_bytes_be();
                let unsigned: u64 = bytes
                    .iter()
                    .rev()
                    .take(8)
                    .enumerate()
                    .map(|(i, &b)| (b as u64) << (i * 8))
                    .sum();
                let signed = unsigned as i64;
                print!("{}", signed);
            } else {
                print_field_value(&values[idx], hex);
            }
            println!();
            idx + 1
        }
        AbiType::String { length } => {
            let len = *length as usize;
            let chars: String = values[idx..idx + len]
                .iter()
                .filter_map(|v| {
                    let bytes = v.into_bigint().to_bytes_be();
                    bytes.last().copied().filter(|&b| b != 0).map(char::from)
                })
                .collect();
            println!("{}{} (str<{}>): \"{}\"", indent_str, name, len, chars);
            idx + len
        }
        AbiType::Array {
            length,
            typ: elem_typ,
        } => {
            let len = *length as usize;
            println!(
                "{}{} ([{}; {}]):",
                indent_str,
                name,
                format_type(elem_typ),
                len
            );
            let mut current_idx = idx;
            for i in 0..len {
                let elem_name = format!("[{}]", i);
                current_idx =
                    print_typed_value(&elem_name, elem_typ, values, current_idx, indent + 1, hex);
            }
            current_idx
        }
        AbiType::Tuple { fields } => {
            println!("{}{} ({}):", indent_str, name, format_type(typ));
            let mut current_idx = idx;
            for (i, field_typ) in fields.iter().enumerate() {
                let field_name = format!(".{}", i);
                current_idx =
                    print_typed_value(&field_name, field_typ, values, current_idx, indent + 1, hex);
            }
            current_idx
        }
        AbiType::Struct { path, fields } => {
            println!("{}{} ({}):", indent_str, name, path);
            let mut current_idx = idx;
            for (field_name, field_typ) in fields {
                let prefixed_name = format!(".{}", field_name);
                current_idx = print_typed_value(
                    &prefixed_name,
                    field_typ,
                    values,
                    current_idx,
                    indent + 1,
                    hex,
                );
            }
            current_idx
        }
    }
}

fn print_field_value(value: &FieldElement, hex: bool) {
    if hex {
        let bytes = value.into_bigint().to_bytes_be();
        print!("0x{}", hex::encode(bytes));
    } else {
        print!("{}", value.into_bigint());
    }
}
