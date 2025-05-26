#[cfg(test)]
use {
    crate::{
        range_check::NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP,
        utils::file_io::deserialize_witness_stack, NoirProofScheme,
    },
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

    let _proof = proof_schema
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

#[test]
fn test_simplest_read_only_memory() {
    test_compiler(
        "../noir-examples/noir-r1cs-test-programs/simplest-read-only-memory/target/main.json",
        "../noir-examples/noir-r1cs-test-programs/simplest-read-only-memory/target/main.gz",
    );
}

#[test]
fn test_read_only_memory() {
    test_compiler(
        "../noir-examples/noir-r1cs-test-programs/read-only-memory/target/main.json",
        "../noir-examples/noir-r1cs-test-programs/read-only-memory/target/main.gz",
    );
}

#[test]
// Test a direct range check (i.e. without a digital decomposition)
fn test_atomic_range_check() {
    assert!(8 <= NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP);
    test_compiler(
        "../noir-examples/noir-r1cs-test-programs/range-check-u8/target/main.json",
        "../noir-examples/noir-r1cs-test-programs/range-check-u8/target/main.gz",
    );
}

#[test]
// Test a range check that requires a digital decomposition
fn test_digital_decomposition_u16() {
    assert!(16 > NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP);
    test_compiler(
        "../noir-examples/noir-r1cs-test-programs/range-check-u16/target/main.json",
        "../noir-examples/noir-r1cs-test-programs/range-check-u16/target/main.gz",
    );
}

#[test]
// Test a range check that requires a digital decomposition mixed bases
// The program compiles to the following ACIR:
//   BrilligCall
//   RANGE CHECK of witness 1 to 238 bits
//   RANGE CHECK of witness 2 to 16 bits
//   BrilligCall
//   RANGE CHECK of witness 7 to 17 bits
//   ..
// + The 238 bit range check is done using a digital decomposition using 29
//   base-2^8 digits and one
// base-2^6 digit.
// + The 16 bit range check is done using a digital decomposition using 2
//   base-2^8 digits.
// + The 17 bit range check is done using a digital decomposition using 2
//   base-2^8 digits and one
// base-2^1 digit.
// Note that the range check of the base-2^1 digit will be done using a direct
// ("naive") range check.
fn test_mixed_base_range_check() {
    test_compiler(
        "../noir-examples/noir-r1cs-test-programs/range-check-mixed-bases/target/main.json",
        "../noir-examples/noir-r1cs-test-programs/range-check-mixed-bases/target/main.gz",
    );
}

#[test]
fn test_read_write_memory() {
    test_compiler(
        "../noir-examples/noir-r1cs-test-programs/read-write-memory/target/main.json",
        "../noir-examples/noir-r1cs-test-programs/read-write-memory/target/main.gz",
    );
}

#[test]
fn test_conditional_write() {
    test_compiler(
        "../noir-examples/noir-r1cs-test-programs/conditional-write/target/main.json",
        "../noir-examples/noir-r1cs-test-programs/conditional-write/target/main.gz",
    );
}

#[test]
fn test_binops() {
    test_compiler(
        "../noir-examples/noir-r1cs-test-programs/bin-opcode/target/main.json",
        "../noir-examples/noir-r1cs-test-programs/bin-opcode/target/main.gz",
    );
}

#[test]
fn test_small_sha() {
    test_compiler(
        "../noir-examples/noir-r1cs-test-programs/small-sha/target/basic.json",
        "../noir-examples/noir-r1cs-test-programs/small-sha/target/basic.gz",
    );
}
