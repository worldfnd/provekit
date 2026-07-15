use {
    crate::in_process::{
        prepare_noir_program_from_json, trim_process_memory, NoirProof, PreparedNoirProgram,
        VerifiedNoirProgram,
    },
    anyhow::{Context, Result},
};

const COMPLETE_AGE_CHECK_PROGRAM: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/complete_age_check.json"
));
const COMPLETE_AGE_CHECK_TOML: &str =
    include_str!("../../noir-examples/noir-passport-monolithic/complete_age_check/Prover.toml");
const FRAGMENTED_ADD_DSC_PROGRAM: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/t_add_dsc_720.json"
));
const FRAGMENTED_ADD_DSC_TOML: &str = include_str!(
    "../../noir-examples/noir-passport/merkle_age_check/benchmark-inputs/tbs_720/t_add_dsc_720.\
     toml"
);
const FRAGMENTED_ADD_ID_DATA_PROGRAM: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/t_add_id_data_720.json"
));
const FRAGMENTED_ADD_ID_DATA_TOML: &str = include_str!(
    "../../noir-examples/noir-passport/merkle_age_check/benchmark-inputs/tbs_720/\
     t_add_id_data_720.toml"
);
const FRAGMENTED_ADD_INTEGRITY_COMMIT_PROGRAM: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/t_add_integrity_commit.json"
));
const FRAGMENTED_ADD_INTEGRITY_COMMIT_TOML: &str = include_str!(
    "../../noir-examples/noir-passport/merkle_age_check/benchmark-inputs/tbs_720/\
     t_add_integrity_commit.toml"
);
const FRAGMENTED_ATTEST_PROGRAM: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/t_attest.json"
));
const FRAGMENTED_ATTEST_TOML: &str = include_str!(
    "../../noir-examples/noir-passport/merkle_age_check/benchmark-inputs/tbs_720/t_attest.toml"
);

pub type PreparedCompleteAgeCheckFixture = PreparedNoirProgram;
pub type VerifiedCompleteAgeCheckFixture = VerifiedNoirProgram;

/// Prepared prover state for the four-stage fragmented age-check fixture.
#[derive(Clone)]
pub struct PreparedFragmentedAgeCheckFixture {
    pub add_dsc:              PreparedNoirProgram,
    pub add_id_data:          PreparedNoirProgram,
    pub add_integrity_commit: PreparedNoirProgram,
    pub attest:               PreparedNoirProgram,
}

/// Verified proof outputs for the four-stage fragmented age-check fixture.
#[derive(Clone)]
pub struct VerifiedFragmentedAgeCheckFixture {
    pub add_dsc:              VerifiedNoirProgram,
    pub add_id_data:          VerifiedNoirProgram,
    pub add_integrity_commit: VerifiedNoirProgram,
    pub attest:               VerifiedNoirProgram,
}

/// Proof-only outputs for the four-stage fragmented age-check fixture.
#[derive(Clone)]
pub struct FragmentedAgeCheckProofs {
    pub add_dsc:              NoirProof,
    pub add_id_data:          NoirProof,
    pub add_integrity_commit: NoirProof,
    pub attest:               NoirProof,
}

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
    let verified = prepared.prove()?;
    trim_process_memory();
    Ok(verified)
}

pub fn prove_complete_age_check_fixture_proof_only(
    prepared: PreparedCompleteAgeCheckFixture,
) -> Result<NoirProof> {
    let proof = prepared.prove_only()?;
    trim_process_memory();
    Ok(proof)
}

pub fn verify_complete_age_check_fixture(
    verified: VerifiedCompleteAgeCheckFixture,
) -> Result<VerifiedCompleteAgeCheckFixture> {
    verified.verify()
}

/// Prepare all four checked-in fragmented age-check stages.
pub fn prepare_fragmented_age_check_fixture() -> Result<PreparedFragmentedAgeCheckFixture> {
    Ok(PreparedFragmentedAgeCheckFixture {
        add_dsc:              prepare_noir_program_from_json(
            "t_add_dsc_720",
            FRAGMENTED_ADD_DSC_PROGRAM,
            FRAGMENTED_ADD_DSC_TOML,
        )
        .context("while preparing t_add_dsc_720 benchmark fixture")?,
        add_id_data:          prepare_noir_program_from_json(
            "t_add_id_data_720",
            FRAGMENTED_ADD_ID_DATA_PROGRAM,
            FRAGMENTED_ADD_ID_DATA_TOML,
        )
        .context("while preparing t_add_id_data_720 benchmark fixture")?,
        add_integrity_commit: prepare_noir_program_from_json(
            "t_add_integrity_commit",
            FRAGMENTED_ADD_INTEGRITY_COMMIT_PROGRAM,
            FRAGMENTED_ADD_INTEGRITY_COMMIT_TOML,
        )
        .context("while preparing t_add_integrity_commit benchmark fixture")?,
        attest:               prepare_noir_program_from_json(
            "t_attest",
            FRAGMENTED_ATTEST_PROGRAM,
            FRAGMENTED_ATTEST_TOML,
        )
        .context("while preparing t_attest benchmark fixture")?,
    })
}

/// Prove every fragmented age-check stage once, dropping verifier state before
/// each proof.
pub fn prove_fragmented_age_check_fixture_proof_only(
    prepared: PreparedFragmentedAgeCheckFixture,
) -> Result<FragmentedAgeCheckProofs> {
    let add_dsc = prepared.add_dsc.prove_only()?;
    trim_process_memory();

    let add_id_data = prepared.add_id_data.prove_only()?;
    trim_process_memory();

    let add_integrity_commit = prepared.add_integrity_commit.prove_only()?;
    trim_process_memory();

    let attest = prepared.attest.prove_only()?;
    trim_process_memory();

    Ok(FragmentedAgeCheckProofs {
        add_dsc,
        add_id_data,
        add_integrity_commit,
        attest,
    })
}

/// Prove every fragmented age-check stage once and return the verified outputs.
pub fn prove_fragmented_age_check_fixture(
    prepared: PreparedFragmentedAgeCheckFixture,
) -> Result<VerifiedFragmentedAgeCheckFixture> {
    let add_dsc = prepared.add_dsc.prove()?;
    trim_process_memory();

    let add_id_data = prepared.add_id_data.prove()?;
    trim_process_memory();

    let add_integrity_commit = prepared.add_integrity_commit.prove()?;
    trim_process_memory();

    let attest = prepared.attest.prove()?;
    trim_process_memory();

    Ok(VerifiedFragmentedAgeCheckFixture {
        add_dsc,
        add_id_data,
        add_integrity_commit,
        attest,
    })
}

/// Verify every fragmented age-check stage proof once.
pub fn verify_fragmented_age_check_fixture(
    verified: VerifiedFragmentedAgeCheckFixture,
) -> Result<VerifiedFragmentedAgeCheckFixture> {
    Ok(VerifiedFragmentedAgeCheckFixture {
        add_dsc:              verified.add_dsc.verify()?,
        add_id_data:          verified.add_id_data.verify()?,
        add_integrity_commit: verified.add_integrity_commit.verify()?,
        attest:               verified.attest.verify()?,
    })
}

pub fn passport_fragmented_age_check_end_to_end_smoke() -> Result<()> {
    let prepared = prepare_fragmented_age_check_fixture()?;
    let verified = prove_fragmented_age_check_fixture(prepared)?;
    let _verified = verify_fragmented_age_check_fixture(verified)?;
    Ok(())
}

pub fn passport_complete_age_check_end_to_end_smoke() -> Result<()> {
    let prepared = prepare_complete_age_check_fixture()?;
    let verified = prove_complete_age_check_fixture(prepared)?;
    let _verified = verify_complete_age_check_fixture(verified)?;
    Ok(())
}
