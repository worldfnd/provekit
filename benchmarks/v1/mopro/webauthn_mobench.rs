//! Mobench functions for the Mopro Circom/Arkworks WebAuthn assertion lane.
//!
//! The zkey is installed as an application resource before the benchmark
//! starts. Fixture discovery and witness preparation happen in Mobench setup
//! callbacks unless the function explicitly measures that phase.

use {
    circom_prover::prover::{self, CircomProof, ProofLib},
    num_bigint::{BigInt, BigUint},
    serde_json::Value,
    std::{
        collections::HashMap,
        env,
        fs,
        hint::black_box,
        path::PathBuf,
        str::FromStr,
        sync::Once,
        thread,
        time::Instant,
    },
};

const INPUTS: &str = include_str!("../test-vectors/circom/input_webauthn_default.json");
const ZKEY_NAME: &str = "webauthn_default_benchmark.zkey";

pub(crate) struct PreparedProve {
    witnesses: Vec<BigUint>,
    zkey_path: String,
}

pub(crate) struct PreparedVerify {
    proof:     CircomProof,
    zkey_path: String,
}

fn zkey_path() -> String {
    if let Some(path) = env::var_os("MOBENCH_WEBAUTHN_ZKEY") {
        return checked_file(PathBuf::from(path));
    }

    #[cfg(target_os = "android")]
    {
        let library_name = format!("lib{}.so", env!("CARGO_PKG_NAME").replace('-', "_"));
        let maps = fs::read_to_string("/proc/self/maps").expect("read Android process maps");
        let library_path = maps
            .lines()
            .filter_map(|line| line.split_whitespace().last())
            .map(|path| path.trim_end_matches(" (deleted)"))
            .find(|path| path.ends_with(&library_name))
            .unwrap_or_else(|| panic!("locate {library_name} in Android process maps"));
        return checked_file(
            PathBuf::from(library_path)
                .parent()
                .expect("Android benchmark library has a parent")
                .join("libmobench_webauthn_zkey.so"),
        );
    }

    #[cfg(not(target_os = "android"))]
    {
        let executable = env::current_exe().expect("resolve benchmark executable path");
        checked_file(
            executable
                .parent()
                .expect("benchmark executable has an app-bundle parent")
                .join(ZKEY_NAME),
        )
    }
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

fn flatten_input(value: &Value, output: &mut Vec<BigInt>) {
    match value {
        Value::Array(values) => {
            for value in values {
                flatten_input(value, output);
            }
        }
        Value::String(value) => {
            output.push(BigInt::from_str(value).expect("decimal Circom input"));
        }
        Value::Number(value) => {
            output.push(BigInt::from_str(&value.to_string()).expect("numeric Circom input"));
        }
        _ => panic!("unsupported Circom input value: {value}"),
    }
}

fn generate_witnesses(inputs: &str) -> Vec<BigUint> {
    let values: Value = serde_json::from_str(inputs).expect("parse WebAuthn inputs");
    let object = values.as_object().expect("WebAuthn inputs are an object");
    let inputs: HashMap<String, Vec<BigInt>> = object
        .iter()
        .map(|(name, value)| {
            let mut flattened = Vec::new();
            flatten_input(value, &mut flattened);
            (name.clone(), flattened)
        })
        .collect();
    super::witness::webauthndefault_witness(inputs)
        .into_iter()
        .map(|value| value.to_biguint().expect("non-negative Circom witness"))
        .collect()
}

fn spawn_witnesses(inputs: String) -> thread::JoinHandle<Vec<BigUint>> {
    thread::spawn(move || generate_witnesses(&inputs))
}

fn prove(prepared: PreparedProve) -> CircomProof {
    prover::prove(
        ProofLib::Arkworks,
        prepared.zkey_path,
        thread::spawn(move || prepared.witnesses),
    )
    .expect("Mopro Arkworks WebAuthn proof")
}

fn validation_gate() {
    static VALIDATED: Once = Once::new();
    VALIDATED.call_once(|| {
        let zkey_path = zkey_path();
        let proof = prove(PreparedProve {
            witnesses: generate_witnesses(INPUTS),
            zkey_path: zkey_path.clone(),
        });
        assert!(
            prover::verify(ProofLib::Arkworks, zkey_path.clone(), proof.clone())
                .expect("verify valid Mopro Arkworks WebAuthn canary"),
            "valid Mopro Arkworks WebAuthn canary was rejected"
        );

        let mut tampered = proof;
        tampered.proof.a.x += BigUint::from(1u32);
        let rejected = match prover::verify(ProofLib::Arkworks, zkey_path, tampered) {
            Ok(valid) => !valid,
            Err(_) => true,
        };
        assert!(
            rejected,
            "tampered Mopro Arkworks WebAuthn canary was accepted"
        );
    });
}

pub(crate) fn setup_inputs() -> String {
    validation_gate();
    INPUTS.to_owned()
}

pub(crate) fn setup_prove() -> PreparedProve {
    validation_gate();
    let zkey_path = zkey_path();
    let zkey_size = fs::metadata(&zkey_path)
        .expect("read WebAuthn zkey metadata")
        .len();
    let input_size = INPUTS.len() as u64;
    mobench_sdk::record_run_u64("zkey_size_bytes", zkey_size);
    mobench_sdk::record_run_u64("input_size_bytes", input_size);
    mobench_sdk::record_run_u64(
        "proving_payload_size_bytes",
        zkey_size + input_size,
    );
    PreparedProve {
        witnesses: generate_witnesses(INPUTS),
        zkey_path,
    }
}

pub(crate) fn setup_verify() -> PreparedVerify {
    validation_gate();
    let zkey_path = zkey_path();
    let proof = prove(PreparedProve {
        witnesses: generate_witnesses(INPUTS),
        zkey_path: zkey_path.clone(),
    });
    assert!(
        prover::verify(ProofLib::Arkworks, zkey_path.clone(), proof.clone())
            .expect("verify prepared Mopro Arkworks WebAuthn proof"),
        "prepared Mopro Arkworks WebAuthn proof must verify"
    );
    PreparedVerify { proof, zkey_path }
}

pub(crate) fn bench_webauthn_arkworks_witness_impl(inputs: String) {
    let witnesses = generate_witnesses(&inputs);
    black_box(witnesses);
}

pub(crate) fn bench_webauthn_arkworks_prove_impl(prepared: PreparedProve) {
    let started = Instant::now();
    let proof = prove(prepared);
    let prove_time_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    let proof_size = serde_json::to_vec(&proof)
        .expect("serialize exact Arkworks Groth16 proof")
        .len() as u64;
    mobench_sdk::record_sample_u64("prove_time_ns", prove_time_ns);
    mobench_sdk::record_sample_u64("proof_size_bytes", proof_size);
    black_box(proof);
}

pub(crate) fn bench_webauthn_arkworks_verify_impl(prepared: &PreparedVerify) {
    let valid = prover::verify(
        ProofLib::Arkworks,
        prepared.zkey_path.clone(),
        prepared.proof.clone(),
    )
    .expect("Mopro Arkworks WebAuthn verification");
    assert!(valid, "valid Mopro Arkworks WebAuthn proof was rejected");
    black_box(valid);
}

pub(crate) fn bench_webauthn_arkworks_e2e_impl(inputs: String) {
    let witnesses = spawn_witnesses(inputs);
    let proof = prover::prove(ProofLib::Arkworks, zkey_path(), witnesses)
        .expect("Mopro Arkworks WebAuthn end-to-end proof");
    let valid = prover::verify(ProofLib::Arkworks, zkey_path(), proof)
        .expect("Mopro Arkworks WebAuthn end-to-end verification");
    assert!(
        valid,
        "end-to-end Mopro Arkworks WebAuthn proof was rejected"
    );
    black_box(valid);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_generates_expected_witness_size() {
        assert_eq!(generate_witnesses(INPUTS).len(), 3_413_073);
    }

    #[test]
    #[ignore = "requires the independently validated SnarkJS WTNS"]
    fn rust_witness_matches_snarkjs_wtns() {
        let path = env::var_os("MOBENCH_WEBAUTHN_WTNS")
            .expect("set MOBENCH_WEBAUTHN_WTNS to the validated fixture");
        let bytes = fs::read(path).expect("read validated SnarkJS WTNS");
        assert_eq!(&bytes[0..4], b"wtns");
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 1);
        let header_len = u64::from_le_bytes(bytes[16..24].try_into().unwrap()) as usize;
        let header = &bytes[24..24 + header_len];
        let field_bytes = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
        let witness_count =
            u32::from_le_bytes(header[4 + field_bytes..8 + field_bytes].try_into().unwrap())
                as usize;
        let section_offset = 24 + header_len;
        assert_eq!(
            u32::from_le_bytes(
                bytes[section_offset..section_offset + 4]
                    .try_into()
                    .unwrap()
            ),
            2
        );
        let witness_data_offset = section_offset + 12;
        let generated = generate_witnesses(INPUTS);
        assert_eq!(generated.len(), witness_count);
        for (index, (expected, actual)) in bytes[witness_data_offset..]
            .chunks_exact(field_bytes)
            .map(BigUint::from_bytes_le)
            .zip(generated)
            .enumerate()
        {
            assert_eq!(actual, expected, "witness mismatch at index {index}");
        }
    }

    #[test]
    #[ignore = "requires the cached 1.6 GiB WebAuthn zkey"]
    fn frozen_fixture_proves_and_verifies() {
        let prepared = setup_verify();
        let proof_json = serde_json::to_vec(&prepared.proof).expect("serialize Circom proof");
        eprintln!("MOPRO_WEBAUTHN_PROOF_JSON_BYTES={}", proof_json.len());
        if let Some(path) = env::var_os("MOBENCH_WEBAUTHN_PROOF_OUTPUT") {
            fs::write(path, proof_json).expect("write retained Circom proof");
        }
        black_box(prepared);
    }
}
