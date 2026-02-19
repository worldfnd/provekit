use {
    super::Command,
    anyhow::{ensure, Context, Result},
    argh::FromArgs,
    ark_ff::{BigInteger, PrimeField},
    noirc_abi::AbiVisibility,
    provekit_common::{file::read, NoirProof, Verifier},
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
            if field_count == 1 {
                print_value(&param.name, &values[idx], self.hex);
                idx += 1;
            } else {
                println!("  {}: [", param.name);
                for i in 0..field_count {
                    print!("    [{}] ", i);
                    print_field_value(&values[idx], self.hex);
                    println!();
                    idx += 1;
                }
                println!("  ]");
            }
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
                if field_count == 1 {
                    print_value("return", &values[idx], self.hex);
                } else {
                    println!("  return: [");
                    for i in 0..field_count {
                        print!("    [{}] ", i);
                        print_field_value(&values[idx + i], self.hex);
                        println!();
                    }
                    println!("  ]");
                }
            }
        }

        Ok(())
    }
}

fn print_value(name: &str, value: &provekit_common::FieldElement, hex: bool) {
    print!("  {}: ", name);
    print_field_value(value, hex);
    println!();
}

fn print_field_value(value: &provekit_common::FieldElement, hex: bool) {
    if hex {
        let bytes = value.into_bigint().to_bytes_be();
        print!("0x{}", hex::encode(bytes));
    } else {
        print!("{}", value.into_bigint());
    }
}
