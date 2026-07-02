//! End-to-end tests for the Zinc+ proving backend: Noir circuit → R1CS →
//! Zinc+ prove → verify, plus tamper rejection and the challenge-free
//! restriction.

use {
    anyhow::Result,
    ark_ff::One,
    nargo::workspace::Workspace,
    nargo_cli::cli::compile_cmd::compile_workspace_full,
    nargo_toml::{resolve_workspace_from_toml, PackageSelection},
    noirc_driver::CompileOptions,
    provekit_common::{file, FieldElement, HashConfig, NoirProof, Prover, Verifier},
    provekit_prover::Prove,
    provekit_r1cs_compiler::NoirCompiler,
    provekit_verifier::Verify,
    serde::Deserialize,
    std::path::{Path, PathBuf},
};

#[derive(Debug, Deserialize)]
struct NargoToml {
    package: NargoTomlPackage,
}

#[derive(Debug, Deserialize)]
struct NargoTomlPackage {
    name: String,
}

fn compile_workspace(workspace_path: impl AsRef<Path>) -> Result<Workspace> {
    let workspace_path = workspace_path.as_ref().join("Nargo.toml").canonicalize()?;
    let workspace =
        resolve_workspace_from_toml(&workspace_path, PackageSelection::DefaultOrAll, None)?;
    compile_workspace_full(&workspace, &CompileOptions::default(), None)?;
    Ok(workspace)
}

/// Compile a Noir example and return its circuit artifact and Prover.toml
/// paths.
fn noir_artifacts(test_case_path: &str) -> (PathBuf, PathBuf) {
    let test_case_path = Path::new(test_case_path);
    compile_workspace(test_case_path).expect("Compiling workspace");
    let nargo_toml =
        std::fs::read_to_string(test_case_path.join("Nargo.toml")).expect("Reading Nargo.toml");
    let nargo_toml: NargoToml = toml::from_str(&nargo_toml).expect("Deserializing Nargo.toml");
    let package_name = nargo_toml.package.name;
    let circuit_path = test_case_path.join(format!("target/{package_name}.json"));
    let witness_file_path = test_case_path.join("Prover.toml");
    (circuit_path, witness_file_path)
}

/// Full roundtrip on a challenge-free circuit with a public input: prepare
/// with the Zinc+ scheme, prove from TOML inputs, serialize/deserialize the
/// proof, verify, and reject tampered public inputs / proof bytes.
#[test]
fn zinc_plus_roundtrip_and_tamper() {
    let (circuit_path, witness_file_path) = noir_artifacts("../../noir-examples/power");

    let scheme = NoirCompiler::from_file(&circuit_path, HashConfig::default())
        .expect("Reading proof scheme")
        .into_zinc_plus()
        .expect("power is challenge-free");

    let prover = Prover::from_noir_proof_scheme(scheme.clone());
    let verifier = Verifier::from_noir_proof_scheme(scheme);
    assert!(
        verifier.whir_for_witness.is_none(),
        "Zinc+ verifier must be marked by whir_for_witness == None"
    );

    let proof = prover
        .prove_with_toml(&witness_file_path)
        .expect("Zinc+ proving");

    // The proof must survive the standard on-disk serialization roundtrip.
    let proof_bytes = file::serialize(&proof).expect("serializing proof");
    let proof: NoirProof = file::deserialize(&proof_bytes).expect("deserializing proof");

    verifier.clone().verify(&proof).expect("Zinc+ verifying");

    // Tampered public input must be rejected.
    let mut bad_proof = proof.clone();
    bad_proof.public_inputs.0[0] += FieldElement::one();
    assert!(
        verifier.clone().verify(&bad_proof).is_err(),
        "tampered public input must be rejected"
    );

    // Tampered proof bytes must be rejected.
    let mut bad_proof = proof.clone();
    let mid = bad_proof.whir_r1cs_proof.narg_string.len() / 2;
    bad_proof.whir_r1cs_proof.narg_string[mid] ^= 0x01;
    assert!(
        verifier.clone().verify(&bad_proof).is_err(),
        "tampered proof bytes must be rejected"
    );
}

/// Circuits that need Fiat-Shamir challenges (memory lookups introduce
/// them) must be rejected at scheme-preparation time.
#[test]
fn zinc_plus_rejects_challenge_circuits() {
    let (circuit_path, _) =
        noir_artifacts("../../noir-examples/noir-r1cs-test-programs/simplest-read-only-memory");

    let err = NoirCompiler::from_file(&circuit_path, HashConfig::default())
        .expect("Reading proof scheme")
        .into_zinc_plus()
        .expect_err("range checks require challenges; must be rejected");
    assert!(
        err.to_string().contains("challenge-free"),
        "unexpected error message: {err}"
    );
}
