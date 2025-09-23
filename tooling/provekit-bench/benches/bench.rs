//! Divan benchmarks for noir-r1cs
use {
    anyhow::Context,
    core::hint::black_box,
    divan::Bencher,
    provekit_common::{file::read, NoirProof, NoirProofScheme},
    provekit_prover::NoirProofSchemeProver,
    provekit_verifier::NoirProofSchemeVerifier,
    std::path::Path,
};

#[divan::bench]
fn read_poseidon_1000(bencher: Bencher) {
    let crate_dir: &Path = "../../noir-examples/poseidon-rounds".as_ref();
    let proof_scheme_path = crate_dir.join("noir-proof-scheme.nps");
    bencher.bench(|| read::<NoirProofScheme>(&proof_scheme_path));
}

#[divan::bench]
fn prove_poseidon_1000(bencher: Bencher) {
    let crate_dir: &Path = "../../noir-examples/poseidon-rounds".as_ref();
    let proof_scheme_path = crate_dir.join("noir-proof-scheme.nps");

    let scheme: NoirProofScheme = read(&proof_scheme_path)
        .with_context(|| format!("Reading {}", proof_scheme_path.display()))
        .expect("Reading proof scheme");

    let witness_path = crate_dir.join("Prover.toml");

    let input_map = scheme
        .read_witness(&witness_path)
        .expect("Failed reading witness");

    bencher.bench(|| black_box(&scheme).prove(black_box(&input_map)));
}

#[divan::bench]
fn prove_poseidon_1000_with_io(bencher: Bencher) {
    let crate_dir: &Path = "../../noir-examples/poseidon-rounds".as_ref();

    let proof_scheme_path = crate_dir.join("noir-proof-scheme.nps");
    let witness_path = crate_dir.join("Prover.toml");

    bencher.bench(|| {
        let scheme: NoirProofScheme = read(&proof_scheme_path)
            .with_context(|| {
                format!(
                    "Failed to read scheme from path: {} (working dir: {:?})",
                    proof_scheme_path.display(),
                    std::env::current_dir().unwrap()
                )
            })
            .expect("Reading proof scheme failed");
        let scheme = black_box(&scheme);
        let input_map = scheme
            .read_witness(&witness_path)
            .with_context(|| {
                format!(
                    "Failed to read witness from path: {} (working dir: {:?})",
                    witness_path.display(),
                    std::env::current_dir().unwrap()
                )
            })
            .expect("Reading witness failed");
        scheme.prove(black_box(&input_map))
    });
}

#[divan::bench]
fn verify_poseidon_1000(bencher: Bencher) {
    let crate_dir: &Path = "../../noir-examples/poseidon-rounds".as_ref();
    let proof_scheme_path = crate_dir.join("noir-proof-scheme.nps");
    let scheme: NoirProofScheme = read(&proof_scheme_path).unwrap();
    let proof_path = crate_dir.join("noir-proof.np");
    let proof: NoirProof = read(&proof_path).unwrap();
    bencher.bench(|| black_box(&scheme).verify(black_box(&proof)));
}

fn main() {
    divan::main();
}
