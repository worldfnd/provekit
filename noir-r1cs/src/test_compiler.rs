use std::fs::File;
use noirc_artifacts::program::ProgramArtifact;
use crate::{compiler::{NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP, R1CS}, solver::MockTranscript, utils::file_io::deserialize_witness_stack};

// Tests that an ACIR program containing a can be compiled to R1CS and
// the R1CS witness solved for given the ACIR witness.
fn test_compilation_and_solving(
    program_path: &str,
    witness_path: &str,
) {
    let file = File::open(program_path).unwrap();
    let program: ProgramArtifact = serde_json::from_reader(file).unwrap();
    let acir_circuit = &program.bytecode.functions[0];
    // Compile the ACIR circuit to R1CS
    let r1cs = R1CS::from_acir(acir_circuit);
    println!("R1CS: {}", r1cs);

    // Solve for the R1CS witness using the ACIR witness
    let mut witness_stack = deserialize_witness_stack(witness_path).unwrap();
    let acir_witness = witness_stack.pop().unwrap().witness;

    let mut transcript = MockTranscript::new();
    let witness = r1cs.solve(&mut transcript, &acir_witness);
    if witness.len() < 100 {
        println!("Witness:");
        for (i, w) in witness.iter().enumerate() {
            println!("w[{}]: {}", i, w);
        }
    } else {
        println!("Witness length: {} (too long to print)", witness.len());
    }

    // Check that the witness satisfies the R1CS relation
    assert!(r1cs.matrices.test_satisfaction(&witness).is_none());
}

#[test]
fn test_brillig_conditional() {
    test_compilation_and_solving(
        "src/test_programs/brillig-conditional/target/main.json",
        "src/test_programs/brillig-conditional/target/main.gz",
    );
}

#[test]
fn test_simplest_read_only() {
    test_compilation_and_solving(
        "src/test_programs/simplest-read-only-memory/target/main.json",
        "src/test_programs/simplest-read-only-memory/target/main.gz",
    );
}

#[test]
fn test_read_only_memory() {
    test_compilation_and_solving(
        "src/test_programs/read-only-memory/target/main.json",
        "src/test_programs/read-only-memory/target/main.gz",
    );
}

#[test]
fn test_read_write_memory() {
    test_compilation_and_solving(
        "src/test_programs/read-write-memory/target/main.json",
        "src/test_programs/read-write-memory/target/main.gz",
    );
}

#[test]
fn test_conditional_write() {
    test_compilation_and_solving(
        "src/test_programs/conditional-write/target/main.json",
        "src/test_programs/conditional-write/target/main.gz",
    );
}

#[test]
// Test a direct range check (i.e. without a digital decomposition)
fn test_atomic_range_check() {
    assert!(8 <= NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP);
    test_compilation_and_solving(
        "src/test_programs/range-check-u8/target/main.json",
        "src/test_programs/range-check-u8/target/main.gz",
    );
}

#[test]
// Test a range check that requires a digital decomposition
fn test_digital_decomposition_u16() {
    assert!(16 > NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP);
    test_compilation_and_solving(
        "src/test_programs/range-check-u16/target/main.json",
        "src/test_programs/range-check-u16/target/main.gz",
    );
}