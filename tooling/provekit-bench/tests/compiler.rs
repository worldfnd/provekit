use {
    anyhow::Result,
    nargo::workspace::Workspace,
    nargo_cli::cli::compile_cmd::compile_workspace_full,
    nargo_toml::{resolve_workspace_from_toml, PackageSelection},
    noirc_driver::CompileOptions,
    provekit_common::{Prover, Verifier},
    provekit_prover::Prove,
    provekit_r1cs_compiler::{MavrosCompiler, NoirCompiler},
    provekit_verifier::Verify,
    serde::Deserialize,
    std::path::Path,
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

fn test_noir_compiler(test_case_path: impl AsRef<Path>, witness_file: &str) {
    let test_case_path = test_case_path.as_ref();

    compile_workspace(test_case_path).expect("Compiling workspace");

    let nargo_toml_path = test_case_path.join("Nargo.toml");

    let nargo_toml = std::fs::read_to_string(&nargo_toml_path).expect("Reading Nargo.toml");
    let nargo_toml: NargoToml = toml::from_str(&nargo_toml).expect("Deserializing Nargo.toml");

    let package_name = nargo_toml.package.name;

    let circuit_path = test_case_path.join(format!("target/{package_name}.json"));
    let witness_file_path = test_case_path.join(witness_file);

    let schema = NoirCompiler::from_file(&circuit_path, provekit_common::HashConfig::default())
        .expect("Reading proof scheme");
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

    let workspace_path = workspace_path.canonicalize()?;

    let workspace =
        resolve_workspace_from_toml(&workspace_path, PackageSelection::DefaultOrAll, None)?;
    let compile_options = CompileOptions::default();

    compile_workspace_full(&workspace, &compile_options, None)?;

    Ok(workspace)
}

#[test_case(
    "../../noir-examples/noir-r1cs-test-programs/acir_assert_zero",
    "Prover.toml"
)]
#[test_case(
    "../../noir-examples/noir-r1cs-test-programs/simplest-read-only-memory",
    "Prover.toml"
)]
#[test_case(
    "../../noir-examples/noir-r1cs-test-programs/read-only-memory",
    "Prover.toml"
)]
#[test_case(
    "../../noir-examples/noir-r1cs-test-programs/range-check-u8",
    "Prover.toml"
)]
#[test_case(
    "../../noir-examples/noir-r1cs-test-programs/range-check-u16",
    "Prover.toml"
)]
#[test_case(
    "../../noir-examples/noir-r1cs-test-programs/range-check-mixed-bases",
    "Prover.toml"
)]
#[test_case(
    "../../noir-examples/noir-r1cs-test-programs/read-write-memory",
    "Prover.toml"
)]
#[test_case(
    "../../noir-examples/noir-r1cs-test-programs/conditional-write",
    "Prover.toml"
)]
#[test_case(
    "../../noir-examples/noir-r1cs-test-programs/bin-opcode",
    "Prover.toml"
)]
#[test_case("../../noir-examples/noir-r1cs-test-programs/small-sha", "Prover.toml")]
#[test_case(
    "../../noir-examples/noir-r1cs-test-programs/bounded-vec",
    "Prover.toml"
)]
#[test_case(
    "../../noir-examples/noir-r1cs-test-programs/brillig-unconstrained",
    "Prover.toml"
)]
#[test_case("../../noir-examples/noir-passport-monolithic/complete_age_check", "Prover.toml"; "complete_age_check")]
#[test_case("../../noir-examples/embedded_curve_msm", "Prover.toml"; "embedded_curve_msm")]
#[test_case("../../noir-examples/embedded_curve_msm", "Prover_zero_scalars.toml"; "msm_zero_scalars")]
#[test_case("../../noir-examples/embedded_curve_msm", "Prover_single_nonzero.toml"; "msm_single_nonzero")]
#[test_case("../../noir-examples/embedded_curve_msm", "Prover_near_order.toml"; "msm_near_order")]
#[test_case("../../noir-examples/embedded_curve_msm", "Prover_near_identity.toml"; "msm_near_identity")]
fn case_noir(path: &str, witness_file: &str) {
    test_noir_compiler(path, witness_file);
}
