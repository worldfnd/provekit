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
const OPRF_PROGRAM: &str =
    include_str!(concat!(env!("OUT_DIR"), "/bench_mobile_fixtures/oprf.json"));
const OPRF_TOML: &str = include_str!("../../noir-examples/oprf/Prover.toml");
const P256_BIGCURVE_PROGRAM: &str =
    include_str!(concat!(env!("OUT_DIR"), "/bench_mobile_fixtures/p256.json"));
const P256_BIGCURVE_TOML: &str = include_str!("../../noir-examples/p256_bigcurve/Prover.toml");

#[derive(Clone, Copy)]
pub enum MobileBenchFixture {
    CompleteAgeCheck,
    Oprf,
    P256Bigcurve,
}

impl MobileBenchFixture {
    fn name(self) -> &'static str {
        match self {
            Self::CompleteAgeCheck => "complete_age_check",
            Self::Oprf => "oprf",
            Self::P256Bigcurve => "p256_bigcurve",
        }
    }

    fn program_json(self) -> &'static str {
        match self {
            Self::CompleteAgeCheck => COMPLETE_AGE_CHECK_PROGRAM,
            Self::Oprf => OPRF_PROGRAM,
            Self::P256Bigcurve => P256_BIGCURVE_PROGRAM,
        }
    }

    fn prover_toml(self) -> &'static str {
        match self {
            Self::CompleteAgeCheck => COMPLETE_AGE_CHECK_TOML,
            Self::Oprf => OPRF_TOML,
            Self::P256Bigcurve => P256_BIGCURVE_TOML,
        }
    }
}

pub type PreparedCircuitFixture = PreparedNoirProgram;
pub type VerifiedCircuitFixture = VerifiedNoirProgram;

pub fn prepare_fixture(fixture: MobileBenchFixture) -> Result<PreparedCircuitFixture> {
    prepare_noir_program_from_json(
        fixture.name(),
        fixture.program_json(),
        fixture.prover_toml(),
    )
    .with_context(|| format!("while preparing {} benchmark fixture", fixture.name()))
}

pub fn prove_fixture(prepared: PreparedCircuitFixture) -> Result<VerifiedCircuitFixture> {
    prepared.prove()
}

pub fn verify_fixture(verified: VerifiedCircuitFixture) -> Result<VerifiedCircuitFixture> {
    verified.verify()
}

pub fn fixture_end_to_end_smoke(fixture: MobileBenchFixture) -> Result<()> {
    let prepared = prepare_fixture(fixture)?;
    let verified = prove_fixture(prepared)?;
    let _verified = verify_fixture(verified)?;
    Ok(())
}
