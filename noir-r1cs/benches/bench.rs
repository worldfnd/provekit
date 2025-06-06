//! Divan benchmarks for noir-r1cs
use {
    core::hint::black_box,
    divan::Bencher,
    noir_r1cs::{read, NoirProof, NoirProofScheme},
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

fn main() {
    divan::main();
}
