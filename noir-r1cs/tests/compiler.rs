use {
    noir_r1cs::NoirProofScheme,
    noir_tools::{compile_workspace, execute_program_witness},
    serde::Deserialize,
    std::path::Path,
    test_case::test_case,
};

#[derive(Debug, Deserialize)]
struct NargoToml {
    package: NargoTomlPackage,
}

#[derive(Debug, Deserialize)]
struct NargoTomlPackage {
    name: String,
}

fn test_compiler(test_case_path: impl AsRef<Path>) {
    let test_case_path = test_case_path.as_ref();

    compile_workspace(test_case_path).expect("Compiling workspace");

    let nargo_toml_path = test_case_path.join("Nargo.toml");

    let nargo_toml = std::fs::read_to_string(&nargo_toml_path).expect("Reading Nargo.toml");
    let nargo_toml: NargoToml = toml::from_str(&nargo_toml).expect("Deserializing Nargo.toml");

    let package_name = nargo_toml.package.name;

    let circuit_path = test_case_path.join(format!("target/{package_name}.json"));
    let witness_file_path = test_case_path.join("Prover.toml");

    let proof_schema = NoirProofScheme::from_file(&circuit_path).expect("Reading proof scheme");

    let witness_map =
        execute_program_witness(circuit_path, &witness_file_path).expect("Executing program");

    let _proof = proof_schema
        .prove(&witness_map)
        .expect("While proving Noir program statement");
}

#[test_case("../noir-examples/noir-r1cs-test-programs/acir_assert_zero")]
#[test_case("../noir-examples/noir-r1cs-test-programs/simplest-read-only-memory")]
#[test_case("../noir-examples/noir-r1cs-test-programs/read-only-memory")]
#[test_case("../noir-examples/noir-r1cs-test-programs/range-check-u8")]
#[test_case("../noir-examples/noir-r1cs-test-programs/range-check-u16")]
#[test_case("../noir-examples/noir-r1cs-test-programs/range-check-mixed-bases")]
#[test_case("../noir-examples/noir-r1cs-test-programs/read-write-memory")]
#[test_case("../noir-examples/noir-r1cs-test-programs/conditional-write")]
#[test_case("../noir-examples/noir-r1cs-test-programs/bin-opcode")]
#[test_case("../noir-examples/noir-r1cs-test-programs/small-sha")]
fn case(path: &str) {
    test_compiler(path);
}
