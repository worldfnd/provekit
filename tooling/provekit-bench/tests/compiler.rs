use {
    anyhow::Result,
    nargo::workspace::Workspace,
    nargo_cli::cli::compile_cmd::compile_workspace_full,
    nargo_toml::{resolve_workspace_from_toml, PackageSelection},
    noirc_driver::CompileOptions,
    provekit_common::{NoirProofScheme, Prover, Verifier},
    provekit_prover::Prove,
    provekit_r1cs_compiler::NoirProofSchemeBuilder,
    provekit_verifier::Verify,
    serde::Deserialize,
    std::path::{Path, PathBuf},
    test_case::test_case,
};

#[derive(Debug, Deserialize)]
struct NargoToml {
    package: NargoTomlPackage,
}

#[derive(Debug, Deserialize)]
struct NargoTomlPackage {
    name: String,
}

/// Ensures each workspace is compiled at most once across parallel test
/// threads. Multiple test cases may share the same Noir workspace.
fn compile_workspace_once(workspace_path: &Path) {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex, OnceLock},
    };

    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<bool>>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));

    let canonical = workspace_path
        .canonicalize()
        .expect("Canonicalizing workspace path");

    let path_lock = {
        let mut map = locks.lock().unwrap();
        map.entry(canonical).or_default().clone()
    };

    let mut compiled = path_lock.lock().unwrap();
    if !*compiled {
        compile_workspace(workspace_path).expect("Compiling workspace");
        *compiled = true;
    }
}

fn test_compiler(test_case_path: impl AsRef<Path>) {
    let test_case_path = test_case_path.as_ref();

    compile_workspace_once(test_case_path);

    let nargo_toml_path = test_case_path.join("Nargo.toml");

    let nargo_toml = std::fs::read_to_string(&nargo_toml_path).expect("Reading Nargo.toml");
    let nargo_toml: NargoToml = toml::from_str(&nargo_toml).expect("Deserializing Nargo.toml");

    let package_name = nargo_toml.package.name;

    let circuit_path = test_case_path.join(format!("target/{package_name}.json"));
    let witness_file_path = test_case_path.join("Prover.toml");

    let schema = NoirProofScheme::from_file(&circuit_path).expect("Reading proof scheme");
    let prover = Prover::from_noir_proof_scheme(schema.clone());
    let mut verifier = Verifier::from_noir_proof_scheme(schema.clone());

    let proof = prover
        .prove_with_toml(&witness_file_path)
        .expect("While proving Noir program statement");

    verifier.verify(&proof).expect("Verifying proof");
}

pub fn compile_workspace(workspace_path: impl AsRef<Path>) -> Result<Workspace> {
    let workspace_path = workspace_path.as_ref();
    let workspace_path = if workspace_path.ends_with("Nargo.toml") {
        workspace_path.to_owned()
    } else {
        workspace_path.join("Nargo.toml")
    };

    // `resolve_workspace_from_toml` calls .normalize() under the hood which messes
    // up path resolution
    let workspace_path = workspace_path.canonicalize()?;

    let workspace =
        resolve_workspace_from_toml(&workspace_path, PackageSelection::DefaultOrAll, None)?;
    let compile_options = CompileOptions::default();

    compile_workspace_full(&workspace, &compile_options, None)?;

    Ok(workspace)
}

#[test_case("../../noir-examples/noir-r1cs-test-programs/acir_assert_zero")]
#[test_case("../../noir-examples/noir-r1cs-test-programs/simplest-read-only-memory")]
#[test_case("../../noir-examples/noir-r1cs-test-programs/read-only-memory")]
#[test_case("../../noir-examples/noir-r1cs-test-programs/range-check-u8")]
#[test_case("../../noir-examples/noir-r1cs-test-programs/range-check-u16")]
#[test_case("../../noir-examples/noir-r1cs-test-programs/range-check-mixed-bases")]
#[test_case("../../noir-examples/noir-r1cs-test-programs/read-write-memory")]
#[test_case("../../noir-examples/noir-r1cs-test-programs/conditional-write")]
#[test_case("../../noir-examples/noir-r1cs-test-programs/bin-opcode")]
#[test_case("../../noir-examples/noir-r1cs-test-programs/small-sha")]
#[test_case("../../noir-examples/noir-r1cs-test-programs/bounded-vec")]
#[test_case("../../noir-examples/noir-r1cs-test-programs/brillig-unconstrained")]
#[test_case("../../noir-examples/noir-passport-monolithic/complete_age_check"; "complete_age_check")]
fn case(path: &str) {
    test_compiler(path);
}

/// Verify that the verifier rejects a proof whose public inputs have been
/// tampered with.
#[test]
fn test_public_input_binding_exploit() {
    use provekit_common::{witness::PublicInputs, FieldElement};

    let test_case_path = Path::new("../../noir-examples/basic-4");

    compile_workspace_once(test_case_path);

    let nargo_toml_path = test_case_path.join("Nargo.toml");
    let nargo_toml = std::fs::read_to_string(&nargo_toml_path).expect("Reading Nargo.toml");
    let nargo_toml: NargoToml = toml::from_str(&nargo_toml).expect("Deserializing Nargo.toml");
    let package_name = nargo_toml.package.name;

    let circuit_path = test_case_path.join(format!("target/{package_name}.json"));
    let witness_file_path = test_case_path.join("Prover.toml");

    let schema = NoirProofScheme::from_file(&circuit_path).expect("Reading proof scheme");
    let prover = Prover::from_noir_proof_scheme(schema.clone());
    let mut verifier = Verifier::from_noir_proof_scheme(schema.clone());

    // Prove honestly (a=5, b=3 -> result = (5+3)*(5-3) = 16)
    let mut proof = prover
        .prove_with_toml(&witness_file_path)
        .expect("While proving Noir program statement");

    // Sanity: honest proof should verify
    {
        let mut honest_verifier = Verifier::from_noir_proof_scheme(schema);
        honest_verifier
            .verify(&proof)
            .expect("Honest proof should verify");
    }

    // Tamper: the committed polynomial encodes result=16 at position 1, but we
    // claim result=42. The verifier should reject this.
    proof.public_inputs = PublicInputs::from_vec(vec![FieldElement::from(42u64)]);

    let result = verifier.verify(&proof);
    assert!(
        result.is_err(),
        "Verification should fail when public inputs are tampered, but it succeeded",
    );
}
