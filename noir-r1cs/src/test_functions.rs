use std::io::Read;
#[cfg(test)]
use {crate::NoirProofScheme, anyhow::Context, std::fs::File, std::path::PathBuf};

#[test]
fn test_acir_assert_zero() {
    let circuit_path = &PathBuf::from(
        "../noir-examples/noir-r1cs-test-programs/acir_assert_zero/target/basic.json",
    );
    let proof_schema = NoirProofScheme::from_file(circuit_path).unwrap();

    let input_file_path =
        &PathBuf::from("../noir-examples/noir-r1cs-test-programs/acir_assert_zero/Prover.toml");
    let mut input_file = File::open(input_file_path)
        .context("while opening input file")
        .unwrap();
    let mut input_toml =
        String::with_capacity(input_file.metadata().map(|m| m.len() as usize).unwrap_or(0));
    input_file
        .read_to_string(&mut input_toml)
        .context("while reading input file")
        .unwrap();

    let proof = proof_schema
        .prove(&input_toml)
        .context("While proving Noir program statement")
        .unwrap();
}
