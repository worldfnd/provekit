use {
    anyhow::{Context, Result},
    noirc_abi::{input_parser::Format, InputMap},
    noirc_artifacts::program::ProgramArtifact,
    provekit_common::{NoirProof, NoirProofScheme, Prover, Verifier},
    provekit_prover::Prove,
    provekit_r1cs_compiler::NoirProofSchemeBuilder,
    provekit_verifier::Verify,
};

const COMPLETE_AGE_CHECK_PROGRAM: &str =
    include_str!("../fixtures/complete_age_check/complete_age_check.json");
const COMPLETE_AGE_CHECK_TOML: &str = include_str!("../fixtures/complete_age_check/Prover.toml");

#[derive(Clone)]
pub struct PreparedCompleteAgeCheckFixture {
    pub prover:    Prover,
    pub verifier:  Verifier,
    pub input_map: InputMap,
}

#[derive(Clone)]
pub struct VerifiedCompleteAgeCheckFixture {
    pub verifier: Verifier,
    pub proof:    NoirProof,
}

fn load_complete_age_check_program() -> Result<ProgramArtifact> {
    serde_json::from_str(COMPLETE_AGE_CHECK_PROGRAM)
        .context("while deserializing complete_age_check program artifact")
}

pub fn prepare_complete_age_check_fixture() -> Result<PreparedCompleteAgeCheckFixture> {
    let program = load_complete_age_check_program()?;
    let scheme = NoirProofScheme::from_program(program)
        .context("while preparing complete_age_check noir proof scheme")?;
    let input_map: InputMap = Format::Toml
        .parse(COMPLETE_AGE_CHECK_TOML, &scheme.witness_generator.abi)
        .context("while parsing complete_age_check prover inputs")?;

    Ok(PreparedCompleteAgeCheckFixture {
        prover: Prover::from_noir_proof_scheme(scheme.clone()),
        verifier: Verifier::from_noir_proof_scheme(scheme),
        input_map,
    })
}

pub fn prove_complete_age_check_fixture(
    prepared: PreparedCompleteAgeCheckFixture,
) -> Result<VerifiedCompleteAgeCheckFixture> {
    let proof = prepared
        .prover
        .prove(prepared.input_map)
        .context("while proving complete_age_check benchmark fixture")?;

    Ok(VerifiedCompleteAgeCheckFixture {
        verifier: prepared.verifier,
        proof,
    })
}

pub fn verify_complete_age_check_fixture(
    mut verified: VerifiedCompleteAgeCheckFixture,
) -> Result<VerifiedCompleteAgeCheckFixture> {
    verified
        .verifier
        .verify(&verified.proof)
        .context("while verifying complete_age_check benchmark fixture")?;

    Ok(verified)
}

pub fn passport_complete_age_check_end_to_end_smoke() -> Result<()> {
    let prepared = prepare_complete_age_check_fixture()?;
    let verified = prove_complete_age_check_fixture(prepared)?;
    let _verified = verify_complete_age_check_fixture(verified)?;
    Ok(())
}
