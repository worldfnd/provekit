//! Divan benchmarks for noir-r1cs
use {
    acir::{native_types::WitnessMap, FieldElement as NoirFieldElement},
    core::hint::black_box,
    divan::Bencher,
    noir_r1cs::{read, utils::file_io::deserialize_witness_stack, NoirProof, NoirProofScheme},
    std::path::{Path, PathBuf},
};

#[divan::bench]
fn read_poseidon_1000(bencher: Bencher) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches")
        .join("poseidon-1000.nps");
    bencher.bench(|| read::<NoirProofScheme>(&path));
}

#[divan::bench]
fn prove_poseidon_1000(bencher: Bencher) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches")
        .join("poseidon-1000.nps");
    let scheme: NoirProofScheme = read(&path).unwrap();

    // Run nargo compile
    let status = std::process::Command::new("nargo")
        .arg("compile")
        .current_dir("../noir-examples/poseidon-rounds")
        .status()
        .expect("Running nargo compile");
    if !status.success() {
        panic!("Failed to run nargo compile");
    }

    // Run nargo execute
    let status = std::process::Command::new("nargo")
        .arg("execute")
        .current_dir("../noir-examples/poseidon-rounds")
        .status()
        .expect("Running nargo execute");
    if !status.success() {
        panic!("Failed to run nargo execute");
    }

    let witness_file_path = &PathBuf::from("../noir-examples/poseidon-rounds/target/basic.gz");
    let mut witness_stack = deserialize_witness_stack(witness_file_path).unwrap();
    let witness_map: WitnessMap<NoirFieldElement> = witness_stack.pop().unwrap().witness;
    bencher.bench(|| black_box(&scheme).prove(black_box(&witness_map)));
}

#[divan::bench]
fn verify_poseidon_1000(bencher: Bencher) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches")
        .join("poseidon-1000.nps");
    let scheme: NoirProofScheme = read(&path).unwrap();
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches")
        .join("poseidon-1000.np");
    let proof: NoirProof = read(&path).unwrap();
    bencher.bench(|| black_box(&scheme).verify(black_box(&proof)));
}

fn main() {
    divan::main();
}
