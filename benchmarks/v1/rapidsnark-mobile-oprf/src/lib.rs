//! Native Mobench adapter for World ID Circom/Rapidsnark OPRF counterparts.
//!
//! Query and nullifier are separate named variants and are packaged as
//! separate apps. Input-to-proof functions generate a fresh WTNS from raw
//! inputs and then prove within one measured region.

use {
    mobench_sdk::benchmark,
    std::{
        env, fs,
        hint::black_box,
        path::{Path, PathBuf},
        sync::Once,
        time::Instant,
    },
};

#[path = "../../rapidsnark-mobile/src/rapidsnark.rs"]
mod rapidsnark;
mod wasmi_witness;

#[cfg(feature = "oprf-query")]
const WITNESS_WASM: &[u8] =
    include_bytes!("../../circom/web/dist/assets/oprf/oprf_query.wasm");
#[cfg(feature = "oprf-nullifier")]
const WITNESS_WASM: &[u8] =
    include_bytes!("../../circom/web/dist/assets/oprf/oprf_nullifier.wasm");

#[cfg(feature = "oprf-query")]
const INPUTS: &str = include_str!("../../circom/web/dist/assets/oprf/oprf_query.input.json");
#[cfg(feature = "oprf-nullifier")]
const INPUTS: &str = include_str!("../../circom/web/dist/assets/oprf/oprf_nullifier.input.json");

#[cfg(all(feature = "oprf-query", feature = "oprf-nullifier"))]
compile_error!("enable exactly one OPRF workload feature");
#[cfg(not(any(feature = "oprf-query", feature = "oprf-nullifier")))]
compile_error!("enable one of oprf-query or oprf-nullifier");

pub struct PreparedProof {
    zkey_path: String,
    witness:   Vec<u8>,
}

pub struct PreparedVerification {
    proof:            rapidsnark::ProofResult,
    verification_key: String,
}

pub struct PreparedProofVerify {
    proof:            PreparedProof,
    verification_key: String,
}

pub struct PreparedInputToProof {
    zkey_path: String,
}

fn generate_witness() -> Vec<u8> {
    wasmi_witness::generate_wtns(WITNESS_WASM, INPUTS).expect("calculate OPRF witness")
}

fn fixture_root() -> PathBuf {
    if let Some(path) = env::var_os("MOBENCH_GROTH16_FIXTURE_ROOT") {
        return PathBuf::from(path);
    }
    env::current_exe()
        .expect("resolve benchmark executable path")
        .parent()
        .expect("benchmark executable has an app-bundle parent")
        .to_path_buf()
}

fn checked_fixture_file(root: &Path, name: &str) -> PathBuf {
    let path = root.join(name);
    let metadata = fs::metadata(&path)
        .unwrap_or_else(|error| panic!("read fixture metadata for {}: {error}", path.display()));
    assert!(
        metadata.is_file(),
        "fixture is not a file: {}",
        path.display()
    );
    path
}

fn load_proof_fixture() -> PreparedProof {
    let root = fixture_root();
    let zkey = checked_fixture_file(&root, "proving_key.zkey");
    let witness_path = checked_fixture_file(&root, "reference.wtns");
    let witness = fs::read(&witness_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", witness_path.display()));
    PreparedProof {
        zkey_path: zkey.to_string_lossy().into_owned(),
        witness,
    }
}

fn verification_key() -> String {
    let path = checked_fixture_file(&fixture_root(), "verification_key.json");
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn prove(prepared: PreparedProof) -> rapidsnark::ProofResult {
    rapidsnark::prove(&prepared.zkey_path, &prepared.witness)
        .expect("Rapidsnark World ID OPRF proof")
}

fn serialized_proof_size(proof: &rapidsnark::ProofResult) -> usize {
    format!(
        r#"{{"proof":{},"public_signals":{}}}"#,
        proof.proof, proof.public_signals
    )
    .len()
}

fn tampered_proof_is_rejected(mut proof: rapidsnark::ProofResult, verification_key: &str) -> bool {
    let digit = proof
        .proof
        .find(|character: char| character.is_ascii_digit())
        .expect("proof JSON contains a digit");
    let replacement = if proof.proof.as_bytes()[digit] == b'0' {
        "1"
    } else {
        "0"
    };
    proof.proof.replace_range(digit..=digit, replacement);
    match rapidsnark::verify(&proof, verification_key) {
        Ok(valid) => !valid,
        Err(_) => true,
    }
}

fn validation_gate() {
    static VALIDATED: Once = Once::new();
    VALIDATED.call_once(|| {
        let verification_key = verification_key();
        let frozen = load_proof_fixture();
        let generated = generate_witness();
        assert_eq!(
            generated, frozen.witness,
            "live OPRF WTNS differs from frozen canary"
        );
        let proof =
            rapidsnark::prove(&frozen.zkey_path, &generated).expect("Rapidsnark live OPRF canary");
        assert!(
            rapidsnark::verify(&proof, &verification_key)
                .expect("verify valid Rapidsnark OPRF canary"),
            "valid Rapidsnark OPRF canary was rejected"
        );
        assert!(
            tampered_proof_is_rejected(proof, &verification_key),
            "tampered Rapidsnark OPRF canary was accepted"
        );
    });
}

fn setup_input_to_proof() -> PreparedInputToProof {
    validation_gate();
    let zkey_path = checked_fixture_file(&fixture_root(), "proving_key.zkey");
    let zkey_size = fs::metadata(&zkey_path)
        .expect("read OPRF zkey metadata")
        .len();
    let wasm_size = env!("MOBENCH_LIVE_WITNESS_WASM_BYTES")
        .parse::<u64>()
        .expect("live witness WASM byte count");
    let input_size = INPUTS.len() as u64;
    mobench_sdk::record_run_u64("zkey_size_bytes", zkey_size);
    mobench_sdk::record_run_u64("witness_wasm_size_bytes", wasm_size);
    mobench_sdk::record_run_u64("input_size_bytes", input_size);
    mobench_sdk::record_run_u64(
        "proving_payload_size_bytes",
        zkey_size + wasm_size + input_size,
    );
    PreparedInputToProof {
        zkey_path: zkey_path.to_string_lossy().into_owned(),
    }
}

fn bench_input_to_proof(prepared: PreparedInputToProof) {
    let input_to_proof_started = Instant::now();
    let witness_started = Instant::now();
    let witness = generate_witness();
    let witness_time_ns = witness_started
        .elapsed()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    let prove_started = Instant::now();
    let proof = rapidsnark::prove(&prepared.zkey_path, &witness)
        .expect("Rapidsnark live-witness OPRF proof");
    let prove_time_ns = prove_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    let input_to_proof_time_ns = input_to_proof_started
        .elapsed()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    mobench_sdk::record_sample_u64("witness_time_ns", witness_time_ns);
    mobench_sdk::record_sample_u64("prove_time_ns", prove_time_ns);
    mobench_sdk::record_sample_u64("input_to_proof_time_ns", input_to_proof_time_ns);
    mobench_sdk::record_sample_u64("proof_size_bytes", serialized_proof_size(&proof) as u64);
    black_box(proof);
}

fn setup_proof() -> PreparedProof {
    validation_gate();
    let root = fixture_root();
    let zkey_size = fs::metadata(checked_fixture_file(&root, "proving_key.zkey"))
        .expect("read OPRF zkey metadata")
        .len();
    let witness_size = fs::metadata(checked_fixture_file(&root, "reference.wtns"))
        .expect("read OPRF witness metadata")
        .len();
    mobench_sdk::record_run_u64("zkey_size_bytes", zkey_size);
    mobench_sdk::record_run_u64("witness_size_bytes", witness_size);
    mobench_sdk::record_run_u64("proving_payload_size_bytes", zkey_size + witness_size);
    load_proof_fixture()
}

fn setup_verification() -> PreparedVerification {
    validation_gate();
    let proof = prove(load_proof_fixture());
    let verification_key = verification_key();
    assert!(
        rapidsnark::verify(&proof, &verification_key)
            .expect("verify prepared Rapidsnark OPRF proof"),
        "prepared Rapidsnark OPRF proof must verify"
    );
    PreparedVerification {
        proof,
        verification_key,
    }
}

fn setup_proof_verify() -> PreparedProofVerify {
    validation_gate();
    PreparedProofVerify {
        proof:            load_proof_fixture(),
        verification_key: verification_key(),
    }
}

macro_rules! benchmarks {
    ($input_to_proof:ident, $prove:ident, $verify:ident, $proof_verify:ident) => {
        #[benchmark(setup = setup_input_to_proof, per_iteration)]
        pub fn $input_to_proof(prepared: PreparedInputToProof) {
            bench_input_to_proof(prepared);
        }

        #[benchmark(setup = setup_proof, per_iteration)]
        pub fn $prove(prepared: PreparedProof) {
            let started = Instant::now();
            let proof = prove(prepared);
            let prove_time_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
            mobench_sdk::record_sample_u64("prove_time_ns", prove_time_ns);
            mobench_sdk::record_sample_u64(
                "proof_size_bytes",
                serialized_proof_size(&proof) as u64,
            );
            black_box(proof);
        }

        #[benchmark(setup = setup_verification)]
        pub fn $verify(prepared: &PreparedVerification) {
            let valid = rapidsnark::verify(&prepared.proof, &prepared.verification_key)
                .expect("Rapidsnark OPRF verification");
            assert!(valid, "valid Rapidsnark OPRF proof was rejected");
            black_box(valid);
        }

        #[benchmark(setup = setup_proof_verify, per_iteration)]
        pub fn $proof_verify(prepared: PreparedProofVerify) {
            let proof = prove(prepared.proof);
            let valid = rapidsnark::verify(&proof, &prepared.verification_key)
                .expect("Rapidsnark OPRF proof-and-verify");
            assert!(valid, "Rapidsnark OPRF proof-and-verify rejected its proof");
            black_box((proof, valid));
        }
    };
}

#[cfg(feature = "oprf-query")]
benchmarks!(
    bench_oprf_query_rapidsnark_input_to_proof,
    bench_oprf_query_rapidsnark_prove,
    bench_oprf_query_rapidsnark_verify,
    bench_oprf_query_rapidsnark_proof_verify
);

#[cfg(feature = "oprf-nullifier")]
benchmarks!(
    bench_oprf_nullifier_rapidsnark_input_to_proof,
    bench_oprf_nullifier_rapidsnark_prove,
    bench_oprf_nullifier_rapidsnark_verify,
    bench_oprf_nullifier_rapidsnark_proof_verify
);

uniffi::setup_scaffolding!();
mobench_sdk::export_native_c_abi!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_three_variant_specific_functions() {
        let names = mobench_sdk::list_benchmark_names();
        assert_eq!(
            names
                .iter()
                .filter(|name| name.contains("oprf_") && name.contains("_rapidsnark_"))
                .count(),
            4,
            "registered benchmarks: {names:?}"
        );
    }

    #[test]
    fn frozen_fixture_proves_verifies_and_rejects_tampering() {
        validation_gate();
    }
}
