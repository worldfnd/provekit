use {
    crate::in_process::{
        prepare_noir_program_from_json, PreparedNoirProgram, PreparedNoirProver,
        VerifiedNoirProgram,
    },
    anyhow::{Context, Result},
    provekit_common::NoirProof,
};

const COMPLETE_AGE_CHECK_PROGRAM: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/complete_age_check.json"
));
const COMPLETE_AGE_CHECK_TOML: &str =
    include_str!("../../noir-examples/noir-passport-monolithic/complete_age_check/Prover.toml");
const OPRF_PROGRAM: &str =
    include_str!(concat!(env!("OUT_DIR"), "/bench_mobile_fixtures/oprf.json"));
const OPRF_TOML: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/oprf.Prover.toml"
));
const PASSPORT_P1_PROGRAM: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/passport_p1.json"
));
const PASSPORT_P1_TOML: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/passport_p1.Prover.toml"
));
const P256_BIGCURVE_PROGRAM: &str =
    include_str!(concat!(env!("OUT_DIR"), "/bench_mobile_fixtures/p256.json"));
const P256_BIGCURVE_TOML: &str = include_str!("../../noir-examples/p256_bigcurve/Prover.toml");
const WEBAUTHN_ASSERTION_PROGRAM: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/webauthn_assertion.json"
));
const WEBAUTHN_ASSERTION_TOML: &str =
    include_str!("../../benchmarks/v1/noir/webauthn_assertion/Prover.toml");

#[derive(Clone, Copy)]
pub enum MobileBenchFixture {
    CompleteAgeCheck,
    Oprf,
    PassportP1,
    P256Bigcurve,
    WebauthnAssertion,
}

impl MobileBenchFixture {
    fn name(self) -> &'static str {
        match self {
            Self::CompleteAgeCheck => "complete_age_check",
            Self::Oprf => "oprf",
            Self::PassportP1 => "passport_p1",
            Self::P256Bigcurve => "p256_bigcurve",
            Self::WebauthnAssertion => "webauthn_assertion",
        }
    }

    fn program_json(self) -> &'static str {
        match self {
            Self::CompleteAgeCheck => COMPLETE_AGE_CHECK_PROGRAM,
            Self::Oprf => OPRF_PROGRAM,
            Self::PassportP1 => PASSPORT_P1_PROGRAM,
            Self::P256Bigcurve => P256_BIGCURVE_PROGRAM,
            Self::WebauthnAssertion => WEBAUTHN_ASSERTION_PROGRAM,
        }
    }

    fn prover_toml(self) -> &'static str {
        match self {
            Self::CompleteAgeCheck => COMPLETE_AGE_CHECK_TOML,
            Self::Oprf => OPRF_TOML,
            Self::PassportP1 => PASSPORT_P1_TOML,
            Self::P256Bigcurve => P256_BIGCURVE_TOML,
            Self::WebauthnAssertion => WEBAUTHN_ASSERTION_TOML,
        }
    }
}

pub type PreparedCircuitFixture = PreparedNoirProgram;
pub type PreparedProverFixture = PreparedNoirProver;
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

pub fn prove_fixture_proof_only(prepared: PreparedProverFixture) -> Result<NoirProof> {
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

#[cfg(test)]
mod tests {
    use super::{prepare_fixture, MobileBenchFixture};

    #[test]
    fn embedded_campaign_artifacts_deserialize_with_provekit_noir() {
        for fixture in [
            MobileBenchFixture::CompleteAgeCheck,
            MobileBenchFixture::Oprf,
            MobileBenchFixture::PassportP1,
            MobileBenchFixture::WebauthnAssertion,
        ] {
            prepare_fixture(fixture)
                .unwrap_or_else(|error| panic!("failed to prepare {}: {error:#}", fixture.name()));
        }
    }
}
