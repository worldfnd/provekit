use {
    anyhow::{Context, Result},
    noirc_abi::{input_parser::Format, InputMap},
    noirc_artifacts::program::ProgramArtifact,
    provekit_common::{HashConfig, NoirProof, Prover, Verifier},
    provekit_prover::Prove,
    provekit_r1cs_compiler::NoirCompiler,
    provekit_verifier::Verify,
};

const COMPLETE_AGE_CHECK_PROGRAM: &str =
    include_str!("../fixtures/complete_age_check/complete_age_check.json");
const COMPLETE_AGE_CHECK_TOML: &str = include_str!("../fixtures/complete_age_check/Prover.toml");
const OPRF_PROGRAM: &str = include_str!("../fixtures/oprf/oprf.json");
const OPRF_TOML: &str = include_str!("../fixtures/oprf/Prover.toml");
const P256_BIGCURVE_PROGRAM: &str = include_str!("../fixtures/p256_bigcurve/p256.json");
const P256_BIGCURVE_TOML: &str = include_str!("../fixtures/p256_bigcurve/Prover.toml");

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

#[derive(Clone)]
pub struct PreparedCircuitFixture {
    pub name:      &'static str,
    pub prover:    Prover,
    pub verifier:  Verifier,
    pub input_map: InputMap,
}

#[derive(Clone)]
pub struct VerifiedCircuitFixture {
    pub name:     &'static str,
    pub verifier: Verifier,
    pub proof:    NoirProof,
}

fn load_program(fixture: MobileBenchFixture) -> Result<ProgramArtifact> {
    serde_json::from_str(fixture.program_json())
        .with_context(|| format!("while deserializing {} program artifact", fixture.name()))
}

pub fn prepare_fixture(fixture: MobileBenchFixture) -> Result<PreparedCircuitFixture> {
    let program = load_program(fixture)?;
    let scheme = NoirCompiler::from_program(program, HashConfig::default())
        .with_context(|| format!("while preparing {} noir proof scheme", fixture.name()))?;
    let input_map: InputMap = Format::Toml
        .parse(fixture.prover_toml(), scheme.abi())
        .with_context(|| format!("while parsing {} prover inputs", fixture.name()))?;

    Ok(PreparedCircuitFixture {
        name: fixture.name(),
        prover: Prover::from_noir_proof_scheme(scheme.clone()),
        verifier: Verifier::from_noir_proof_scheme(scheme),
        input_map,
    })
}

pub fn prove_fixture(prepared: PreparedCircuitFixture) -> Result<VerifiedCircuitFixture> {
    let proof = prepared
        .prover
        .prove(prepared.input_map)
        .with_context(|| format!("while proving {} benchmark fixture", prepared.name))?;

    Ok(VerifiedCircuitFixture {
        name: prepared.name,
        verifier: prepared.verifier,
        proof,
    })
}

pub fn verify_fixture(mut verified: VerifiedCircuitFixture) -> Result<VerifiedCircuitFixture> {
    verified
        .verifier
        .verify(&verified.proof)
        .with_context(|| format!("while verifying {} benchmark fixture", verified.name))?;

    Ok(verified)
}

pub fn fixture_end_to_end_smoke(fixture: MobileBenchFixture) -> Result<()> {
    let prepared = prepare_fixture(fixture)?;
    let verified = prove_fixture(prepared)?;
    let _verified = verify_fixture(verified)?;
    Ok(())
}
