use {
    anyhow::Result,
    nargo::{
        insert_all_files_for_workspace_into_file_manager,
        ops::{check_program, collect_errors, compile_program, report_errors},
        parse_all,
        workspace::Workspace,
    },
    nargo_toml::{resolve_workspace_from_toml, PackageSelection},
    noir_artifact_cli::fs::artifact::save_program_to_file,
    noirc_driver::{CompilationResult, CompileOptions},
    provekit_common::{Format, NoirProofScheme, Prover, Verifier},
    provekit_prover::Prove,
    provekit_r1cs_compiler::NoirProofSchemeBuilder,
    provekit_verifier::Verify,
    rayon::prelude::*,
    serde::Deserialize,
    std::{
        path::{Path, PathBuf},
        sync::Arc,
    },
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
        sync::{Mutex, OnceLock},
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

    let mut file_manager = workspace.new_file_manager();
    insert_all_files_for_workspace_into_file_manager(&workspace, &mut file_manager);
    let file_manager = Arc::new(file_manager);
    let parsed_files = Arc::new(parse_all(&file_manager));
    let target_dir = workspace.target_directory_path();
    let binary_packages: Vec<_> = workspace.into_iter().filter(|p| p.is_binary()).collect();

    // Large programs overflow the default 2 MB thread stack while compiling.
    let pool = rayon::ThreadPoolBuilder::new()
        .stack_size(4 * 1024 * 1024)
        .build()?;
    let results: Vec<CompilationResult<()>> = pool.install(|| {
        binary_packages
            .par_iter()
            .map(|package| {
                let (program, warnings) = compile_program(
                    &file_manager,
                    &parsed_files,
                    &workspace,
                    package,
                    &compile_options,
                    None,
                )?;
                check_program(&program)?;
                save_program_to_file(&program.into(), &package.name, &target_dir)
                    .expect("saving program artifact");
                Ok(((), warnings))
            })
            .collect()
    });

    report_errors(
        collect_errors(results),
        &file_manager,
        &parsed_files,
        compile_options.deny_warnings,
        compile_options.silence_warnings,
    )?;

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
#[test_case("../../noir-examples/noir-r1cs-test-programs/struct-array-memory")]
#[test_case("../../noir-examples/noir-r1cs-test-programs/bin-opcode")]
#[test_case("../../noir-examples/noir-r1cs-test-programs/small-sha")]
#[test_case("../../noir-examples/noir-r1cs-test-programs/bounded-vec")]
#[test_case("../../noir-examples/noir-r1cs-test-programs/brillig-unconstrained")]
#[test_case("../../noir-examples/noir-passport-monolithic/complete_age_check"; "complete_age_check")]
fn case(path: &str) {
    test_compiler(path);
}

/// Verify that `prove_with_inputs` produces a valid proof for both explicit
/// `Format::Json` and `Format::Toml` variants.
#[test]
fn test_prove_with_inputs_json_and_toml() {
    let test_case_path = Path::new("../../noir-examples/basic-4");

    compile_workspace_once(test_case_path);

    let nargo_toml_path = test_case_path.join("Nargo.toml");
    let nargo_toml = std::fs::read_to_string(&nargo_toml_path).expect("Reading Nargo.toml");
    let nargo_toml: NargoToml = toml::from_str(&nargo_toml).expect("Deserializing Nargo.toml");
    let package_name = nargo_toml.package.name;

    let circuit_path = test_case_path.join(format!("target/{package_name}.json"));
    let schema = NoirProofScheme::from_file(&circuit_path).expect("Reading proof scheme");

    let json_inputs = r#"{"a": "5", "b": "3"}"#;
    let json_proof = Prover::from_noir_proof_scheme(schema.clone())
        .prove_with_inputs(json_inputs, Format::Json)
        .expect("Proving from JSON inputs");
    Verifier::from_noir_proof_scheme(schema.clone())
        .verify(&json_proof)
        .expect("Verifying JSON-sourced proof");

    let toml_inputs = "a = \"5\"\nb = \"3\"\n";
    let toml_proof = Prover::from_noir_proof_scheme(schema.clone())
        .prove_with_inputs(toml_inputs, Format::Toml)
        .expect("Proving from TOML inputs");
    Verifier::from_noir_proof_scheme(schema)
        .verify(&toml_proof)
        .expect("Verifying TOML-sourced proof");
}

/// Verify that `NoirProof::encode` / `decode` roundtrips losslessly.
#[test]
fn test_noir_proof_encode_decode_roundtrip() {
    let test_case_path = Path::new("../../noir-examples/basic-4");

    compile_workspace_once(test_case_path);

    let nargo_toml_path = test_case_path.join("Nargo.toml");
    let nargo_toml = std::fs::read_to_string(&nargo_toml_path).expect("Reading Nargo.toml");
    let nargo_toml: NargoToml = toml::from_str(&nargo_toml).expect("Deserializing Nargo.toml");
    let package_name = nargo_toml.package.name;

    let circuit_path = test_case_path.join(format!("target/{package_name}.json"));
    let schema = NoirProofScheme::from_file(&circuit_path).expect("Reading proof scheme");

    let proof = Prover::from_noir_proof_scheme(schema)
        .prove_with_inputs(r#"{"a": "5", "b": "3"}"#, Format::Json)
        .expect("Proving");

    let encoded = proof.encode().expect("encode");
    let decoded = provekit_common::NoirProof::decode(&encoded).expect("decode");

    // Re-encoding the decoded proof must be byte-identical to the first
    // encoding — this proves the wire form roundtrips. (We can't assert
    // structural equality because `WhirR1CSProof::pattern` is `skip_serializing`,
    // and we can't re-verify the decoded proof in debug builds because the
    // whir verifier asserts `!pattern.is_empty()`.)
    let reencoded = decoded.encode().expect("re-encode");
    assert_eq!(
        encoded, reencoded,
        "encoded form must be stable under roundtrip"
    );
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
    assert_eq!(schema.r1cs.num_public_inputs, 1);
    let prover = Prover::from_noir_proof_scheme(schema.clone());
    let mut verifier = Verifier::from_noir_proof_scheme(schema.clone());

    // Prove honestly (a=5, b=3 -> result = (5+3)*(5-3) = 16)
    let mut proof = prover
        .prove_with_toml(&witness_file_path)
        .expect("While proving Noir program statement");

    // Sanity: honest proof should verify
    {
        let mut honest_verifier = Verifier::from_noir_proof_scheme(schema.clone());
        honest_verifier
            .verify(&proof)
            .expect("Honest proof should verify");
    }

    for values in [vec![], vec![
        FieldElement::from(16u64),
        FieldElement::from(42u64),
    ]] {
        let mut wrong_count = proof.clone();
        wrong_count.public_inputs = PublicInputs::from_vec(values);
        let error = Verifier::from_noir_proof_scheme(schema.clone())
            .verify(&wrong_count)
            .expect_err("Wrong public-input count should fail");
        assert!(error.to_string().contains("Public input count mismatch"));
    }

    let mut legacy_schema = schema.clone();
    legacy_schema.r1cs.num_public_inputs = 0;
    legacy_schema.whir_for_witness.r1cs_hash = legacy_schema.r1cs.hash();
    let error = Verifier::from_noir_proof_scheme(legacy_schema)
        .verify(&proof)
        .expect_err("Legacy public-input declaration should fail");
    assert!(error.to_string().contains("public-input declaration"));

    let mut mismatched_schema = schema.clone();
    mismatched_schema.r1cs.num_public_inputs = 2;
    let error = Verifier::from_noir_proof_scheme(mismatched_schema)
        .verify(&proof)
        .expect_err("Unauthenticated public-input count should fail");
    assert!(error.to_string().contains("R1CS hash mismatch"));

    // Tamper: the committed polynomial encodes result=16 at position 1, but we
    // claim result=42. The verifier should reject this.
    proof.public_inputs = PublicInputs::from_vec(vec![FieldElement::from(42u64)]);

    let result = verifier.verify(&proof);
    assert!(
        result.is_err(),
        "Verification should fail when public inputs are tampered, but it succeeded",
    );
}

/// Noir bounds an index into an array of multi-field elements with the memory
/// opcode alone, so an out-of-range address must not yield an accepted proof.
#[test]
fn test_out_of_bounds_memory_address_is_rejected() {
    use acir::circuit::Opcode;

    let test_case_path =
        Path::new("../../noir-examples/noir-r1cs-test-programs/struct-array-memory");

    compile_workspace_once(test_case_path);

    let circuit_path = test_case_path.join("target/main.json");
    let schema = NoirProofScheme::from_file(&circuit_path).expect("Reading proof scheme");

    // Widen every memory block by one element so the solver accepts index 4
    // and returns a witness that satisfies everything except the memory checks
    // of the unmodified circuit.
    let mut widened = Prover::from_noir_proof_scheme(schema.clone());
    let mut blocks = 0;
    for opcode in &mut widened.program.functions[0].opcodes {
        if let Opcode::MemoryInit { init, .. } = opcode {
            assert_eq!(init.len(), 8, "four elements of two fields each");
            init.extend_from_within(..2);
            blocks += 1;
        }
    }
    assert_eq!(blocks, 2, "one read-only and one read-write block");

    let elements: String = (1..=4)
        .map(|i| format!("[[pairs]]\na = {i}\nb = {i}\n\n[[scratch]]\na = {i}\nb = {i}\n\n"))
        .collect();

    for (rom_read, ram_write, ram_read) in [(4, 1, 1), (2, 4, 1), (2, 1, 4)] {
        let inputs = format!(
            "rom_read = {rom_read}\nram_write = {ram_write}\nram_read = {ram_read}\n\n{elements}"
        );
        let input_map = Format::Toml
            .parse(&inputs, widened.witness_generator.abi())
            .expect("Parsing inputs");
        let forged = widened
            .clone()
            .generate_witness(input_map)
            .expect("an explicit bounds check is back: forge the witness another way");

        let accepted = Prover::from_noir_proof_scheme(schema.clone())
            .prove_with_witness(forged)
            .is_ok_and(|proof| {
                Verifier::from_noir_proof_scheme(schema.clone())
                    .verify(&proof)
                    .is_ok()
            });
        assert!(
            !accepted,
            "accepted rom_read={rom_read} ram_write={ram_write} ram_read={ram_read}"
        );
    }
}
