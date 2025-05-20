#[cfg(test)]
use {
    crate::{utils::file_io::deserialize_witness_stack, NoirProofScheme},
    acir::native_types::WitnessMap,
    acir_field::FieldElement as AcirFieldElement,
    anyhow::Context,
    std::path::PathBuf,
};

#[cfg(test)]
fn test_compiler(circuit_path_str: &str, witness_path_str: &str) {
    let circuit_path = &PathBuf::from(circuit_path_str);
    let proof_schema = NoirProofScheme::from_file(circuit_path).unwrap();

    let witness_file_path = &PathBuf::from(witness_path_str);
    let mut witness_stack = deserialize_witness_stack(witness_file_path).unwrap();
    let witness_map: WitnessMap<AcirFieldElement> = witness_stack.pop().unwrap().witness;

    let proof = proof_schema
        .prove(&witness_map)
        .context("While proving Noir program statement")
        .unwrap();
}

#[test]
fn test_acir_assert_zero() {
    test_compiler(
        "../noir-examples/noir-r1cs-test-programs/acir_assert_zero/target/basic.json",
        "../noir-examples/noir-r1cs-test-programs/acir_assert_zero/target/basic.gz",
    );
}
