//! Mobench functions for the native Mopro Noir/Barretenberg lanes.
//!
//! The proof-only functions retain frozen beta.19 `WitnessStack` files for the
//! historical campaign. The input-to-proof functions parse the frozen raw
//! Prover TOML, execute ACVM, serialize the resulting witness, and prove inside
//! one measured region.

use {
    noir_rs::{
        acir::{native_types::{WitnessMap, WitnessStack}, FieldElement},
        barretenberg::{
            api::{
                circuit_prove, configure_memory, proof_fields_to_bytes,
                settings_ultra_honk_poseidon2,
            },
            srs::setup_srs_from_bytecode,
            verify::{get_ultra_honk_verification_key, verify_ultra_honk},
        },
        circuit::get_acir_buffer_uncompressed,
        execute::execute,
        witness::serialize_witness,
    },
    noirc_abi::{input_parser::Format, Abi},
    serde_json::Value,
    std::{
        env, fs,
        hint::black_box,
        path::PathBuf,
        sync::{Once, OnceLock},
        time::Instant,
    },
};

const SRS_NAME: &str = "noir_beta19_campaign.dat";
const WEBAUTHN_CIRCUIT: &str = include_str!("../test-vectors/noir/campaign/webauthn/circuit.json");
const WEBAUTHN_WITNESS: &[u8] = include_bytes!("../test-vectors/noir/campaign/webauthn/witness.gz");
const WEBAUTHN_INPUT: &str = include_str!("../test-vectors/noir/campaign/webauthn/Prover.toml");
const PASSPORT_CIRCUIT: &str = include_str!("../test-vectors/noir/campaign/passport/circuit.json");
const PASSPORT_WITNESS: &[u8] = include_bytes!("../test-vectors/noir/campaign/passport/witness.gz");
const PASSPORT_INPUT: &str = include_str!("../test-vectors/noir/campaign/passport/Prover.toml");
const PASSPORT_P1_CIRCUIT: &str = include_str!("../test-vectors/noir/campaign/passport_p1/circuit.json");
const PASSPORT_P1_WITNESS: &[u8] = include_bytes!("../test-vectors/noir/campaign/passport_p1/witness.gz");
const PASSPORT_P1_INPUT: &str = include_str!("../test-vectors/noir/campaign/passport_p1/Prover.toml");
const OPRF_CIRCUIT: &str = include_str!("../test-vectors/noir/campaign/oprf/circuit.json");
const OPRF_WITNESS: &[u8] = include_bytes!("../test-vectors/noir/campaign/oprf/witness.gz");
const OPRF_INPUT: &str = include_str!("../test-vectors/noir/campaign/oprf/Prover.toml");

#[derive(Clone)]
pub(crate) struct PreparedProve {
    bytecode:           &'static str,
    verification_key:   Vec<u8>,
    serialized_witness: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct PreparedInputToProof {
    workload:         &'static FrozenWorkload,
    verification_key: Vec<u8>,
}

pub(crate) struct PreparedVerify {
    proof:            Vec<u8>,
    verification_key: Vec<u8>,
}

struct FrozenWorkload {
    name:               &'static str,
    bytecode:           &'static str,
    serialized_witness: Vec<u8>,
    abi:                Abi,
    input_toml:         &'static str,
    circuit_size_bytes: usize,
    witness_size_bytes: usize,
    input_size_bytes:   usize,
}

fn checked_file(path: PathBuf) -> String {
    let metadata = fs::metadata(&path)
        .unwrap_or_else(|error| panic!("read fixture metadata for {}: {error}", path.display()));
    assert!(
        metadata.is_file(),
        "fixture is not a file: {}",
        path.display()
    );
    path.to_string_lossy().into_owned()
}

fn srs_path() -> String {
    if let Some(path) = env::var_os("MOBENCH_NOIR_SRS") {
        return checked_file(PathBuf::from(path));
    }
    let executable = env::current_exe().expect("resolve benchmark executable path");
    checked_file(
        executable
            .parent()
            .expect("benchmark executable has an app-bundle parent")
            .join(SRS_NAME),
    )
}

fn load_workload(
    name: &'static str,
    circuit_json: &'static str,
    witness_bytes: &'static [u8],
    input_toml: &'static str,
) -> FrozenWorkload {
    let circuit: Value = serde_json::from_str(circuit_json).expect("parse frozen Noir circuit");
    let bytecode = circuit["bytecode"]
        .as_str()
        .expect("frozen Noir circuit has bytecode")
        .to_owned();
    // Each workload is initialized once, so retaining one decoded bytecode
    // string for the process lifetime is bounded and avoids repeated parsing.
    let bytecode = Box::leak(bytecode.into_boxed_str());
    let abi = serde_json::from_value(circuit["abi"].clone()).expect("parse frozen Noir ABI");

    let stack: WitnessStack<FieldElement> =
        WitnessStack::deserialize(witness_bytes).expect("decode frozen beta.19 WitnessStack");
    assert_eq!(
        stack.length(),
        1,
        "frozen benchmark must contain one witness frame"
    );
    let serialized_witness =
        serialize_witness(stack).expect("serialize solved witness for Barretenberg");
    FrozenWorkload {
        name,
        bytecode,
        serialized_witness,
        abi,
        input_toml,
        circuit_size_bytes: circuit_json.len(),
        witness_size_bytes: witness_bytes.len(),
        input_size_bytes: input_toml.len(),
    }
}

fn webauthn() -> &'static FrozenWorkload {
    static WORKLOAD: OnceLock<FrozenWorkload> = OnceLock::new();
    WORKLOAD.get_or_init(|| load_workload("webauthn", WEBAUTHN_CIRCUIT, WEBAUTHN_WITNESS, WEBAUTHN_INPUT))
}

fn oprf() -> &'static FrozenWorkload {
    static WORKLOAD: OnceLock<FrozenWorkload> = OnceLock::new();
    WORKLOAD.get_or_init(|| load_workload("oprf", OPRF_CIRCUIT, OPRF_WITNESS, OPRF_INPUT))
}

fn passport() -> &'static FrozenWorkload {
    static WORKLOAD: OnceLock<FrozenWorkload> = OnceLock::new();
    WORKLOAD.get_or_init(|| load_workload("passport", PASSPORT_CIRCUIT, PASSPORT_WITNESS, PASSPORT_INPUT))
}

fn passport_p1() -> &'static FrozenWorkload {
    static WORKLOAD: OnceLock<FrozenWorkload> = OnceLock::new();
    WORKLOAD.get_or_init(|| load_workload(
        "passport_p1",
        PASSPORT_P1_CIRCUIT,
        PASSPORT_P1_WITNESS,
        PASSPORT_P1_INPUT,
    ))
}

fn prepare(workload: &'static FrozenWorkload) -> PreparedProve {
    setup_srs_from_bytecode(workload.bytecode, Some(&srs_path()), false)
        .expect("initialize frozen Noir SRS");
    let verification_key = get_ultra_honk_verification_key(workload.bytecode, true)
        .expect("compute native Noir verification key");
    PreparedProve {
        bytecode: workload.bytecode,
        verification_key,
        serialized_witness: workload.serialized_witness.clone(),
    }
}

fn prove(prepared: PreparedProve) -> Vec<u8> {
    configure_memory(true, None);
    let acir = get_acir_buffer_uncompressed(prepared.bytecode)
        .expect("decode frozen Noir circuit for Barretenberg");
    let response = circuit_prove(
        &acir,
        &prepared.serialized_witness,
        &prepared.verification_key,
        &settings_ultra_honk_poseidon2(),
    )
    .expect("native Mopro Noir proof");
    let mut proof = (response.public_inputs.len() as u32).to_be_bytes().to_vec();
    proof.extend(proof_fields_to_bytes(&response.public_inputs));
    proof.extend(proof_fields_to_bytes(&response.proof));
    proof
}

fn initial_witness(workload: &FrozenWorkload) -> WitnessMap<FieldElement> {
    let inputs = Format::Toml
        .parse(workload.input_toml, &workload.abi)
        .expect("parse frozen Noir Prover TOML");
    workload
        .abi
        .encode(&inputs, None)
        .expect("encode frozen Noir inputs")
}

fn solve_witness(workload: &FrozenWorkload) -> Vec<u8> {
    let witness = execute(workload.bytecode, initial_witness(workload))
        .expect("execute native Noir witness generation");
    serialize_witness(witness).expect("serialize live native Noir witness")
}

fn prove_serialized(
    bytecode: &'static str,
    verification_key: &[u8],
    serialized_witness: &[u8],
) -> Vec<u8> {
    configure_memory(true, None);
    let acir = get_acir_buffer_uncompressed(bytecode)
        .expect("decode frozen Noir circuit for Barretenberg");
    let response = circuit_prove(
        &acir,
        serialized_witness,
        verification_key,
        &settings_ultra_honk_poseidon2(),
    )
    .expect("native Mopro Noir proof");
    let mut proof = (response.public_inputs.len() as u32).to_be_bytes().to_vec();
    proof.extend(proof_fields_to_bytes(&response.public_inputs));
    proof.extend(proof_fields_to_bytes(&response.proof));
    proof
}

fn prepare_input_to_proof(workload: &'static FrozenWorkload) -> PreparedInputToProof {
    setup_srs_from_bytecode(workload.bytecode, Some(&srs_path()), false)
        .expect("initialize frozen Noir SRS");
    let verification_key = get_ultra_honk_verification_key(workload.bytecode, true)
        .expect("compute native Noir verification key");
    PreparedInputToProof {
        workload,
        verification_key,
    }
}

fn validate(workload: &'static FrozenWorkload, gate: &'static Once) {
    gate.call_once(|| {
        let prepared = prepare_input_to_proof(workload);
        let verification_key = prepared.verification_key.clone();
        let witness = solve_witness(workload);
        let mut proof = prove_serialized(workload.bytecode, &verification_key, &witness);
        assert!(
            verify_ultra_honk(proof.clone(), verification_key.clone())
                .expect("verify valid native Noir canary"),
            "valid native Noir canary was rejected"
        );
        let proof_size_bytes = proof.len();
        let middle = proof.len() / 2;
        proof[middle] ^= 1;
        let rejected = match verify_ultra_honk(proof, verification_key) {
            Ok(valid) => !valid,
            Err(_) => true,
        };
        assert!(rejected, "tampered native Noir canary was accepted");
        let srs_size_bytes = fs::metadata(srs_path())
            .expect("read native Noir SRS metadata")
            .len();
        println!(
            "MOBENCH_METRIC_JSON {}",
            serde_json::json!({
                "schema_version": 1,
                "stack": "noir_barretenberg",
                "workload": workload.name,
                "proof_size_bytes": proof_size_bytes,
                "proving_payload": {
                    "circuit_size_bytes": workload.circuit_size_bytes,
                    "witness_size_bytes": workload.witness_size_bytes,
                    "srs_size_bytes": srs_size_bytes,
                    "deduplicated_total_bytes": workload.circuit_size_bytes as u64
                        + workload.witness_size_bytes as u64
                        + srs_size_bytes,
                },
                "tampered_proof_rejected": true,
                "timing_scope": "outside_measured_region",
            })
        );
    });
}

fn record_proving_payload(workload: &'static FrozenWorkload) {
    let srs_size_bytes = fs::metadata(srs_path())
        .expect("read native Noir SRS metadata")
        .len();
    mobench_sdk::record_run_u64("circuit_size_bytes", workload.circuit_size_bytes as u64);
    mobench_sdk::record_run_u64("witness_size_bytes", workload.witness_size_bytes as u64);
    mobench_sdk::record_run_u64("srs_size_bytes", srs_size_bytes);
    mobench_sdk::record_run_u64(
        "proving_payload_size_bytes",
        workload.circuit_size_bytes as u64
            + workload.witness_size_bytes as u64
            + srs_size_bytes,
    );
}

fn record_input_to_proof_payload(workload: &'static FrozenWorkload) {
    let srs_size_bytes = fs::metadata(srs_path())
        .expect("read native Noir SRS metadata")
        .len();
    mobench_sdk::record_run_u64("circuit_size_bytes", workload.circuit_size_bytes as u64);
    mobench_sdk::record_run_u64("input_size_bytes", workload.input_size_bytes as u64);
    mobench_sdk::record_run_u64("srs_size_bytes", srs_size_bytes);
    mobench_sdk::record_run_u64(
        "proving_payload_size_bytes",
        workload.circuit_size_bytes as u64 + workload.input_size_bytes as u64 + srs_size_bytes,
    );
}

fn setup_prove(workload: &'static FrozenWorkload, gate: &'static Once) -> PreparedProve {
    validate(workload, gate);
    record_proving_payload(workload);
    prepare(workload)
}

fn setup_verify(workload: &'static FrozenWorkload, gate: &'static Once) -> PreparedVerify {
    validate(workload, gate);
    let prepared = prepare(workload);
    let verification_key = prepared.verification_key.clone();
    let proof = prove(prepared);
    assert!(
        verify_ultra_honk(proof.clone(), verification_key.clone())
            .expect("verify prepared native Noir proof"),
        "prepared native Noir proof was rejected"
    );
    PreparedVerify {
        proof,
        verification_key,
    }
}

static WEBAUTHN_VALIDATED: Once = Once::new();
static PASSPORT_VALIDATED: Once = Once::new();
static PASSPORT_P1_VALIDATED: Once = Once::new();
static OPRF_VALIDATED: Once = Once::new();

pub(crate) fn setup_webauthn_prove() -> PreparedProve {
    setup_prove(webauthn(), &WEBAUTHN_VALIDATED)
}

pub(crate) fn setup_webauthn_verify() -> PreparedVerify {
    setup_verify(webauthn(), &WEBAUTHN_VALIDATED)
}

pub(crate) fn setup_oprf_prove() -> PreparedProve {
    setup_prove(oprf(), &OPRF_VALIDATED)
}

pub(crate) fn setup_passport_prove() -> PreparedProve {
    setup_prove(passport(), &PASSPORT_VALIDATED)
}

pub(crate) fn setup_passport_verify() -> PreparedVerify {
    setup_verify(passport(), &PASSPORT_VALIDATED)
}

pub(crate) fn setup_oprf_verify() -> PreparedVerify {
    setup_verify(oprf(), &OPRF_VALIDATED)
}

fn setup_input_to_proof(
    workload: &'static FrozenWorkload,
    gate: &'static Once,
) -> PreparedInputToProof {
    validate(workload, gate);
    record_input_to_proof_payload(workload);
    prepare_input_to_proof(workload)
}

pub(crate) fn setup_webauthn_input_to_proof() -> PreparedInputToProof {
    setup_input_to_proof(webauthn(), &WEBAUTHN_VALIDATED)
}

pub(crate) fn setup_passport_input_to_proof() -> PreparedInputToProof {
    setup_input_to_proof(passport(), &PASSPORT_VALIDATED)
}

pub(crate) fn setup_passport_p1_input_to_proof() -> PreparedInputToProof {
    setup_input_to_proof(passport_p1(), &PASSPORT_P1_VALIDATED)
}

pub(crate) fn setup_oprf_input_to_proof() -> PreparedInputToProof {
    setup_input_to_proof(oprf(), &OPRF_VALIDATED)
}

pub(crate) fn bench_input_to_proof_impl(prepared: PreparedInputToProof) {
    let input_to_proof_started = Instant::now();
    let witness_started = Instant::now();
    let serialized_witness = solve_witness(prepared.workload);
    let witness_time_ns = witness_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    let prove_started = Instant::now();
    let proof = prove_serialized(
        prepared.workload.bytecode,
        &prepared.verification_key,
        &serialized_witness,
    );
    let prove_time_ns = prove_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    let input_to_proof_time_ns = input_to_proof_started
        .elapsed()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    mobench_sdk::record_sample_u64("witness_time_ns", witness_time_ns);
    mobench_sdk::record_sample_u64("prove_time_ns", prove_time_ns);
    mobench_sdk::record_sample_u64("input_to_proof_time_ns", input_to_proof_time_ns);
    mobench_sdk::record_sample_u64("proof_size_bytes", proof.len() as u64);
    black_box(proof);
}

pub(crate) fn bench_prove_impl(prepared: PreparedProve) {
    let started = Instant::now();
    let proof = prove(prepared);
    let prove_time_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    mobench_sdk::record_sample_u64("prove_time_ns", prove_time_ns);
    mobench_sdk::record_sample_u64("proof_size_bytes", proof.len() as u64);
    black_box(proof);
}

pub(crate) fn bench_verify_impl(prepared: &PreparedVerify) {
    let valid = verify_ultra_honk(prepared.proof.clone(), prepared.verification_key.clone())
        .expect("native Mopro Noir verification");
    assert!(valid, "valid native Mopro Noir proof was rejected");
    black_box(valid);
}

pub(crate) fn bench_proof_verify_impl(prepared: PreparedProve) {
    let verification_key = prepared.verification_key.clone();
    let proof = prove(prepared);
    let valid =
        verify_ultra_honk(proof, verification_key).expect("native Mopro Noir proof-and-verify");
    assert!(
        valid,
        "native Mopro Noir proof-and-verify rejected its proof"
    );
    black_box(valid);
}
