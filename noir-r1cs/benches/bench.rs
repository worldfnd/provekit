//! Divan benchmarks for noir-r1cs
use {
    bincode,
    core::hint::black_box,
    divan::Bencher,
    noir_r1cs::{
        read, utils::sumcheck::calculate_external_row_of_r1cs_matrices, FieldElement, NoirProof,
        NoirProofScheme, R1CS,
    },
    noir_tools::compile_workspace,
    std::path::Path,
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

    compile_workspace(crate_dir).expect("Compiling workspace");

    let witness_path = crate_dir.join("Prover.toml");

    let input_map = scheme
        .read_witness(&witness_path)
        .expect("Failed reading witness");

    bencher.bench(|| black_box(&scheme).prove(black_box(&input_map)));
}

#[divan::bench]
fn prove_poseidon_1000_with_io(bencher: Bencher) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches")
        .join("poseidon-1000.nps");

    let crate_dir: &Path = "../noir-examples/poseidon-rounds".as_ref();
    let witness_path = crate_dir.join("Prover.toml");

    compile_workspace(crate_dir).expect("Compiling workspace");

    bencher.bench(|| {
        let scheme: NoirProofScheme = read(&path).unwrap();
        let scheme = black_box(&scheme);
        let input_map = scheme.read_witness(&witness_path).unwrap();
        scheme.prove(black_box(&input_map))
    });
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

#[divan::bench]
fn calculate_external_row_from_serialized_data(bencher: Bencher) {
    let alpha_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches")
        .join("alpha.bin");
    let r1cs_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches")
        .join("r1cs.bin");

    // Load serialized data with bincode
    let alpha_raw: Vec<u64> =
        bincode::deserialize(&std::fs::read(&alpha_path).expect("Failed to read alpha.bin"))
            .expect("Failed to deserialize alpha");
    let alpha: Vec<FieldElement> = alpha_raw
        .into_iter()
        .map(|v| FieldElement::from(v))
        .collect();

    let r1cs: R1CS =
        bincode::deserialize(&std::fs::read(&r1cs_path).expect("Failed to read r1cs.bin"))
            .expect("Failed to deserialize r1cs");

    bencher.bench(|| {
        black_box(calculate_external_row_of_r1cs_matrices(
            black_box(&alpha),
            black_box(&r1cs),
        ))
    });
}

fn main() {
    divan::main();
}
