//! Divan benchmarks for noir-r1cs
use {
    acir::{native_types::WitnessMap, FieldElement as NoirFieldElement},
    core::hint::black_box,
    divan::Bencher,
    noir_r1cs::{read, utils::file_io::deserialize_witness_stack, NoirProof, NoirProofScheme},
    noir_tools::execute_program_witness,
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

    let crate_dir: &Path = "../noir-examples/poseidon-rounds".as_ref();

    // Run nargo compile
    let status = std::process::Command::new("nargo")
        .arg("compile")
        .current_dir(crate_dir)
        .status()
        .expect("Running nargo compile");
    if !status.success() {
        panic!("Failed to run nargo compile");
    }

    let program_path = crate_dir.join("target/basic.json");
    let witness_path = crate_dir.join("Prover.toml");

    let witness_map = execute_program_witness(program_path, witness_path).unwrap();

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
