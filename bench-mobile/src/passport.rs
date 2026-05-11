use {
    anyhow::{Context, Result},
    provekit_ffi::in_process::{
        prepare_noir_program_from_json, PreparedNoirProgram, VerifiedNoirProgram,
    },
};

const COMPLETE_AGE_CHECK_PROGRAM: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/complete_age_check.json"
));
const COMPLETE_AGE_CHECK_TOML: &str =
    include_str!("../../noir-examples/noir-passport-monolithic/complete_age_check/Prover.toml");

pub type PreparedCompleteAgeCheckFixture = PreparedNoirProgram;
pub type VerifiedCompleteAgeCheckFixture = VerifiedNoirProgram;

pub fn prepare_complete_age_check_fixture() -> Result<PreparedCompleteAgeCheckFixture> {
    prepare_noir_program_from_json(
        "complete_age_check",
        COMPLETE_AGE_CHECK_PROGRAM,
        COMPLETE_AGE_CHECK_TOML,
    )
    .context("while preparing complete_age_check benchmark fixture")
}

pub fn prove_complete_age_check_fixture(
    prepared: PreparedCompleteAgeCheckFixture,
) -> Result<VerifiedCompleteAgeCheckFixture> {
    prepared.prove()
}

pub fn verify_complete_age_check_fixture(
    verified: VerifiedCompleteAgeCheckFixture,
) -> Result<VerifiedCompleteAgeCheckFixture> {
    verified.verify()
}

pub fn passport_complete_age_check_end_to_end_smoke() -> Result<()> {
    let prepared = prepare_complete_age_check_fixture()?;
    let verified = prove_complete_age_check_fixture(prepared)?;
    let _verified = verify_complete_age_check_fixture(verified)?;
    Ok(())
}
