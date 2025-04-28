use crate::{compiler::R1CS, solver::MockTranscript, utils::file_io::deserialize_witness_stack};
use noirc_artifacts::program::ProgramArtifact;
use std::fs::File;

// Tests that an ACIR program containing a can be compiled to R1CS and
// the R1CS witness solved for given the ACIR witness.
fn test_compilation_and_solving(program_path: &str, witness_path: &str) {
    let file = File::open(program_path).unwrap();
    let program: ProgramArtifact = serde_json::from_reader(file).unwrap();
    let acir_circuit = &program.bytecode.functions[0];
    // Compile the ACIR circuit to R1CS
    let r1cs = R1CS::from_acir(acir_circuit);

    // Solve for the R1CS witness using the ACIR witness
    let mut witness_stack = deserialize_witness_stack(witness_path).unwrap();
    let acir_witness = witness_stack.pop().unwrap().witness;

    let mut transcript = MockTranscript::new();
    let witness = r1cs.solver.solve(&mut transcript, &acir_witness);

    // Check that the witness satisfies the R1CS relation
    let satisfaction_test = r1cs.matrices.test_satisfaction(&witness);
    dbg!(&satisfaction_test);
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
fn test_read_only_memory() {
    test_compilation_and_solving(
        "src/test_programs/read-only-memory/target/main.json",
        "src/test_programs/read-only-memory/target/main.gz",
    );
}

#[test]
#[ignore]
fn test_read_write_memory() {
    test_compilation_and_solving(
        "src/test_programs/read-write-memory/target/main.json",
        "src/test_programs/read-write-memory/target/main.gz",
    );
}

#[test]
fn test_range() {
    test_compilation_and_solving(
        "src/test_programs/range-check/target/main.json",
        "src/test_programs/range-check/target/main.gz",
    );
}

#[test]
fn test_bin_opcode() {
    test_compilation_and_solving(
        "src/test_programs/bin-opcode/target/main.json",
        "src/test_programs/bin-opcode/target/main.gz",
    );
}

#[test]
fn test_complete_age_check() {
    test_compilation_and_solving(
        "../noir-examples/noir-passport-examples/complete_age_check/target/complete_age_check.json",
        "../noir-examples/noir-passport-examples/complete_age_check/target/complete_age_check.gz",
    );
}

#[test]
fn test_small_sha() {
    test_compilation_and_solving(
        "src/test_programs/small-sha/target/main.json",
        "src/test_programs/small-sha/target/main.gz",
    );
}
