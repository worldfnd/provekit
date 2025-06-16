//! Standalone executable for profiling noir-r1cs prove operations
use {
    noir_r1cs::{read, NoirProofScheme},
    noir_tools::compile_workspace,
    std::path::Path,
};

fn main() {
    println!("Starting prove profiling...");

    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let poseidon_path = manifest_path.join("benches").join("poseidon-1000.nps");
    let scheme: NoirProofScheme = read(&poseidon_path).unwrap();

    let crate_dir = manifest_path.join("../noir-examples/poseidon-rounds");

    compile_workspace(&crate_dir).expect("Compiling workspace");

    let witness_path = crate_dir.join("Prover.toml");

    let input_map = scheme
        .read_witness(&witness_path)
        .expect("Failed reading witness");

    println!("Setup complete, starting prove operations...");

    // Run multiple iterations for better profiling data
    for i in 0..1 {
        println!("Prove iteration {}", i + 1);

        let _proof = scheme.prove(&input_map);
    }

    println!("Profiling complete!");
}
