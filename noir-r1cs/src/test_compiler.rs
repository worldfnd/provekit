use std::fs::File;
use noirc_artifacts::program::ProgramArtifact;
use crate::{compiler::R1CS, solver::MockTranscript, utils::file_io::deserialize_witness_stack};

// Tests that a simple ACIR program containing a read-only memory block can be compile to R1CS and
// the witness solved for.
#[test]
fn test_read_only_memory() {
    let file = File::open("src/test_programs/read-only-memory/target/main.json").unwrap();
    let program: ProgramArtifact = serde_json::from_reader(file).unwrap();
    let acir_circuit = &program.bytecode.functions[0];
    // Compile the ACIR circuit to R1CS
    let r1cs = R1CS::from_acir(acir_circuit);

    // Solve for the R1CS witness using the ACIR witness
    let mut witness_stack = deserialize_witness_stack("src/test_programs/read-only-memory/target/main.gz").unwrap();
    let acir_witness = witness_stack.pop().unwrap().witness;

    let mut transcript = MockTranscript::new();
    let witness = r1cs.solver.solve(&mut transcript, &acir_witness);

    // Check that the witness satisfies the R1CS relation
    assert!(r1cs.matrices.test_satisfaction(&witness).is_none());
}