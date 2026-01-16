use {
    anyhow::Result,
    nargo::workspace::Workspace,
    nargo_cli::cli::compile_cmd::compile_workspace_full,
    nargo_toml::{resolve_workspace_from_toml, PackageSelection},
    noirc_driver::CompileOptions,
    provekit_common::{
        blake3::{Blake3MerkleConfig, Blake3PoW},
        keccak::{KeccakMerkleConfig, KeccakPoW},
        sha256::{Sha256MerkleConfig, Sha256PoW},
        skyscraper::{SkyscraperMerkleConfig, SkyscraperPoW},
        NoirProofScheme, Prover, Verifier,
    },
    provekit_prover::Prove,
    provekit_r1cs_compiler::NoirProofSchemeBuilder,
    provekit_verifier::Verify,
    serde::Deserialize,
    std::path::Path,
};

#[derive(Debug, Deserialize)]
struct NargoToml {
    package: NargoTomlPackage,
}

#[derive(Debug, Deserialize)]
struct NargoTomlPackage {
    name: String,
}

/// Helper to get circuit and witness paths from a test case path.
fn get_paths(test_case_path: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    compile_workspace(test_case_path).expect("Compiling workspace");

    let nargo_toml_path = test_case_path.join("Nargo.toml");
    let nargo_toml = std::fs::read_to_string(&nargo_toml_path).expect("Reading Nargo.toml");
    let nargo_toml: NargoToml = toml::from_str(&nargo_toml).expect("Deserializing Nargo.toml");
    let package_name = nargo_toml.package.name;

    let circuit_path = test_case_path.join(format!("target/{package_name}.json"));
    let witness_file_path = test_case_path.join("Prover.toml");

    (circuit_path, witness_file_path)
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

macro_rules! e2e_tests {
    ($mod_name:ident, $merkle:ty, $pow:ty, $suffix:literal) => {
        mod $mod_name {
            use super::*;

            fn test_e2e(test_case_path: impl AsRef<Path>) {
                let test_case_path = test_case_path.as_ref();
                let (circuit_path, witness_file_path) = get_paths(test_case_path);

                // Prepare step: create proof scheme, prover, and verifier
                let schema: NoirProofScheme<$merkle, $pow> =
                    NoirProofScheme::from_file(&circuit_path).expect("Reading proof scheme");
                let prover: Prover<$merkle, $pow> = Prover::from_noir_proof_scheme(schema.clone());
                let mut verifier: Verifier<$merkle, $pow> =
                    Verifier::from_noir_proof_scheme(schema);

                // Prove step
                let proof = prover
                    .prove(&witness_file_path)
                    .expect("While proving Noir program statement");

                // Verify step
                verifier.verify(&proof).expect("Verifying proof");
            }

            #[test]
            fn acir_assert_zero() {
                test_e2e("../../noir-examples/noir-r1cs-test-programs/acir_assert_zero");
            }

            #[test]
            fn simplest_read_only_memory() {
                test_e2e("../../noir-examples/noir-r1cs-test-programs/simplest-read-only-memory");
            }

            #[test]
            fn read_only_memory() {
                test_e2e("../../noir-examples/noir-r1cs-test-programs/read-only-memory");
            }

            #[test]
            fn range_check_u8() {
                test_e2e("../../noir-examples/noir-r1cs-test-programs/range-check-u8");
            }

            #[test]
            fn range_check_u16() {
                test_e2e("../../noir-examples/noir-r1cs-test-programs/range-check-u16");
            }

            #[test]
            fn range_check_mixed_bases() {
                test_e2e("../../noir-examples/noir-r1cs-test-programs/range-check-mixed-bases");
            }

            #[test]
            fn read_write_memory() {
                test_e2e("../../noir-examples/noir-r1cs-test-programs/read-write-memory");
            }

            #[test]
            fn conditional_write() {
                test_e2e("../../noir-examples/noir-r1cs-test-programs/conditional-write");
            }

            #[test]
            fn bin_opcode() {
                test_e2e("../../noir-examples/noir-r1cs-test-programs/bin-opcode");
            }

            #[test]
            fn small_sha() {
                test_e2e("../../noir-examples/noir-r1cs-test-programs/small-sha");
            }

            #[test]
            fn complete_age_check() {
                test_e2e("../../noir-examples/noir-passport-examples/complete_age_check");
            }
        }
    };
}

// Generate e2e tests for all hash configurations
e2e_tests!(skyscraper, SkyscraperMerkleConfig, SkyscraperPoW, "");
e2e_tests!(sha256, Sha256MerkleConfig, Sha256PoW, "_sha256");
e2e_tests!(keccak, KeccakMerkleConfig, KeccakPoW, "_keccak");
e2e_tests!(blake3, Blake3MerkleConfig, Blake3PoW, "_blake3");
