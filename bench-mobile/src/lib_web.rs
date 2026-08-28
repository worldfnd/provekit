//! Browser-only Mobench adapter for the ProveKit V1 publication workloads.
//!
//! The secretless preparation job generates the witness files embedded here.
//! Browser samples measure proof generation only. The first setup for each
//! workload additionally verifies a valid proof and rejects a tampered proof.

use {
    acir::native_types::WitnessMap,
    mobench_sdk::{benchmark, profile_phase},
    noirc_artifacts::program::ProgramArtifact,
    provekit_common::{NoirElement, NoirProof, NoirProofScheme, Prover, Verifier},
    provekit_prover::Prove,
    provekit_r1cs_compiler::NoirProofSchemeBuilder,
    provekit_verifier::Verify,
    std::{hint::black_box, sync::Once},
};

#[cfg(feature = "web-passport-complete")]
const COMPLETE_AGE_CHECK_PROGRAM: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/complete_age_check.json"
));
#[cfg(feature = "web-passport-complete")]
const COMPLETE_AGE_CHECK_WITNESS: &[u8] =
    include_bytes!("../generated/wasm/complete_age_check.witness.postcard");
#[cfg(feature = "web-passport-fragmented")]
const FRAGMENTED_ADD_DSC_PROGRAM: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/t_add_dsc_720.json"
));
#[cfg(feature = "web-passport-fragmented")]
const FRAGMENTED_ADD_DSC_WITNESS: &[u8] =
    include_bytes!("../generated/wasm/t_add_dsc_720.witness.postcard");
#[cfg(feature = "web-passport-fragmented")]
const FRAGMENTED_ADD_ID_DATA_PROGRAM: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/t_add_id_data_720.json"
));
#[cfg(feature = "web-passport-fragmented")]
const FRAGMENTED_ADD_ID_DATA_WITNESS: &[u8] =
    include_bytes!("../generated/wasm/t_add_id_data_720.witness.postcard");
#[cfg(feature = "web-passport-fragmented")]
const FRAGMENTED_ADD_INTEGRITY_COMMIT_PROGRAM: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/t_add_integrity_commit.json"
));
#[cfg(feature = "web-passport-fragmented")]
const FRAGMENTED_ADD_INTEGRITY_COMMIT_WITNESS: &[u8] =
    include_bytes!("../generated/wasm/t_add_integrity_commit.witness.postcard");
#[cfg(feature = "web-passport-fragmented")]
const FRAGMENTED_ATTEST_PROGRAM: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/t_attest.json"
));
#[cfg(feature = "web-passport-fragmented")]
const FRAGMENTED_ATTEST_WITNESS: &[u8] =
    include_bytes!("../generated/wasm/t_attest.witness.postcard");
#[cfg(feature = "web-webauthn")]
const WEBAUTHN_ASSERTION_PROGRAM: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/bench_mobile_fixtures/webauthn_assertion.json"
));
#[cfg(feature = "web-webauthn")]
const WEBAUTHN_ASSERTION_WITNESS: &[u8] =
    include_bytes!("../generated/wasm/webauthn_assertion.witness.postcard");
#[cfg(feature = "web-oprf")]
const OPRF_PROGRAM: &str =
    include_str!(concat!(env!("OUT_DIR"), "/bench_mobile_fixtures/oprf.json"));
#[cfg(feature = "web-oprf")]
const OPRF_WITNESS: &[u8] = include_bytes!("../generated/wasm/oprf.witness.postcard");

#[cfg(feature = "web-passport-complete")]
static COMPLETE_GATE: Once = Once::new();
#[cfg(feature = "web-passport-fragmented")]
static FRAGMENTED_GATE: Once = Once::new();
#[cfg(feature = "web-webauthn")]
static WEBAUTHN_GATE: Once = Once::new();
#[cfg(feature = "web-oprf")]
static OPRF_GATE: Once = Once::new();

/// Browser-ready ProveKit prover and its precomputed Noir witness.
pub struct PreparedCircuit {
    prover:  Prover,
    witness: WitnessMap<NoirElement>,
}

#[cfg(feature = "web-passport-fragmented")]
/// Browser-ready prover state for all four fragmented passport stages.
pub struct PreparedFragmented {
    circuits: Vec<PreparedCircuit>,
}

fn parse_fixture(
    program_json: &str,
    witness_bytes: &[u8],
) -> (NoirProofScheme, WitnessMap<NoirElement>) {
    let program: ProgramArtifact =
        serde_json::from_str(program_json).expect("deserialize browser benchmark program");
    let scheme =
        NoirProofScheme::from_program(program).expect("prepare browser benchmark proof scheme");
    let witness =
        postcard::from_bytes(witness_bytes).expect("deserialize browser benchmark witness");
    (scheme, witness)
}

fn validate_proof_gate(scheme: NoirProofScheme, witness: WitnessMap<NoirElement>) {
    let proof = Prover::from_noir_proof_scheme(scheme.clone())
        .prove_with_witness(witness)
        .expect("prove browser validation canary");
    Verifier::from_noir_proof_scheme(scheme.clone())
        .verify(&proof)
        .expect("verify browser validation canary");

    let mut tampered = proof;
    let byte = tampered
        .whir_r1cs_proof
        .narg_string
        .first_mut()
        .expect("proof transcript must not be empty");
    *byte ^= 1;
    assert!(
        Verifier::from_noir_proof_scheme(scheme)
            .verify(&tampered)
            .is_err(),
        "tampered browser validation canary must be rejected"
    );
}

fn prepare_single(
    program_json: &str,
    witness_bytes: &[u8],
    gate: &'static Once,
) -> PreparedCircuit {
    let (scheme, witness) = parse_fixture(program_json, witness_bytes);
    gate.call_once(|| validate_proof_gate(scheme.clone(), witness.clone()));
    PreparedCircuit {
        prover: Prover::from_noir_proof_scheme(scheme),
        witness,
    }
}

#[cfg(feature = "web-passport-complete")]
fn setup_complete_age_check() -> PreparedCircuit {
    prepare_single(
        COMPLETE_AGE_CHECK_PROGRAM,
        COMPLETE_AGE_CHECK_WITNESS,
        &COMPLETE_GATE,
    )
}

#[cfg(feature = "web-passport-fragmented")]
fn setup_fragmented_age_check() -> PreparedFragmented {
    let fixture_specs = [
        (FRAGMENTED_ADD_DSC_PROGRAM, FRAGMENTED_ADD_DSC_WITNESS),
        (
            FRAGMENTED_ADD_ID_DATA_PROGRAM,
            FRAGMENTED_ADD_ID_DATA_WITNESS,
        ),
        (
            FRAGMENTED_ADD_INTEGRITY_COMMIT_PROGRAM,
            FRAGMENTED_ADD_INTEGRITY_COMMIT_WITNESS,
        ),
        (FRAGMENTED_ATTEST_PROGRAM, FRAGMENTED_ATTEST_WITNESS),
    ];
    let parsed: Vec<_> = fixture_specs
        .into_iter()
        .map(|(program, witness)| parse_fixture(program, witness))
        .collect();
    FRAGMENTED_GATE.call_once(|| {
        for (scheme, witness) in &parsed {
            validate_proof_gate(scheme.clone(), witness.clone());
        }
    });
    PreparedFragmented {
        circuits: parsed
            .into_iter()
            .map(|(scheme, witness)| PreparedCircuit {
                prover: Prover::from_noir_proof_scheme(scheme),
                witness,
            })
            .collect(),
    }
}

#[cfg(feature = "web-webauthn")]
fn setup_webauthn_assertion() -> PreparedCircuit {
    prepare_single(
        WEBAUTHN_ASSERTION_PROGRAM,
        WEBAUTHN_ASSERTION_WITNESS,
        &WEBAUTHN_GATE,
    )
}

#[cfg(feature = "web-oprf")]
fn setup_oprf() -> PreparedCircuit {
    prepare_single(OPRF_PROGRAM, OPRF_WITNESS, &OPRF_GATE)
}

fn prove(prepared: PreparedCircuit) -> NoirProof {
    prepared
        .prover
        .prove_with_witness(prepared.witness)
        .expect("prove browser benchmark fixture")
}

#[cfg(feature = "web-passport-complete")]
#[benchmark(setup = setup_complete_age_check, per_iteration)]
pub fn bench_passport_complete_age_check_prove(prepared: PreparedCircuit) {
    black_box(profile_phase("prove", || prove(prepared)));
}

#[cfg(feature = "web-passport-fragmented")]
#[benchmark(setup = setup_fragmented_age_check, per_iteration)]
pub fn bench_passport_fragmented_age_check_prove(prepared: PreparedFragmented) {
    let proofs = profile_phase("prove", || {
        prepared.circuits.into_iter().map(prove).collect::<Vec<_>>()
    });
    black_box(proofs);
}

#[cfg(feature = "web-webauthn")]
#[benchmark(setup = setup_webauthn_assertion, per_iteration)]
pub fn bench_webauthn_assertion_prove(prepared: PreparedCircuit) {
    black_box(profile_phase("prove", || prove(prepared)));
}

#[cfg(feature = "web-oprf")]
#[benchmark(setup = setup_oprf, per_iteration)]
pub fn bench_oprf_prove(prepared: PreparedCircuit) {
    black_box(profile_phase("prove", || prove(prepared)));
}
