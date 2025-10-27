//! Divan benchmarks for noir-r1cs
use {
    anyhow::Context,
    core::hint::black_box,
    divan::Bencher,
    provekit_common::{file::read, NoirProof, Prover, Verifier},
    provekit_prover::Prove,
    provekit_verifier::Verify,
    std::path::Path,
};

#[divan::bench]
fn read_poseidon_1000(bencher: Bencher) {
    let crate_dir: &Path = "../../noir-examples/poseidon-rounds".as_ref();
    let proof_prover_path = crate_dir.join("noir-provekit-prover.pkp");
    bencher.bench(|| read::<Prover>(&proof_prover_path));
}

#[divan::bench]
fn prove_poseidon_1000(bencher: Bencher) {
    let crate_dir: &Path = "../../noir-examples/poseidon-rounds".as_ref();
    let proof_prover_path = crate_dir.join("noir-provekit-prover.pkp");

    let mut prover: Prover = read(&proof_prover_path)
        .with_context(|| format!("Reading {}", proof_prover_path.display()))
        .expect("Reading prover");

    let witness_path = crate_dir.join("Prover.toml");

    bencher.bench_local(|| black_box(&mut prover).prove(black_box(&witness_path)));
}

#[divan::bench]
fn prove_poseidon_1000_with_io(bencher: Bencher) {
    let crate_dir: &Path = "../../noir-examples/poseidon-rounds".as_ref();

    let proof_prover_path = crate_dir.join("noir-provekit-prover.pkp");
    let witness_path = crate_dir.join("Prover.toml");

    bencher.bench(|| {
        let prover: Prover = read(&proof_prover_path)
            .with_context(|| {
                format!(
                    "Failed to read scheme from path: {} (working dir: {:?})",
                    proof_prover_path.display(),
                    std::env::current_dir().unwrap()
                )
            })
            .expect("Reading prover failed");
        let mut prover = black_box(prover);
        prover.prove(black_box(&witness_path))
    });
}

#[divan::bench]
fn verify_poseidon_1000(bencher: Bencher) {
    let crate_dir: &Path = "../../noir-examples/poseidon-rounds".as_ref();
    let proof_verifier_path = crate_dir.join("noir-provekit-verifier.pkv");
    let mut verifier: Verifier = read(&proof_verifier_path).unwrap();
    let proof_path = crate_dir.join("noir-proof.np");
    let proof: NoirProof = read(&proof_path).unwrap();
    bencher.bench_local(|| black_box(&mut verifier).verify(black_box(&proof)));
}

fn main() {
    divan::main();
}
