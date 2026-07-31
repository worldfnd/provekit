//! Native Mobench adapter for the Circom/Rapidsnark passport lanes.
//!
//! The large proving key and reference witness are installed as ordinary app
//! resources. They are resolved and read before each timed iteration; only the
//! native Groth16 prover call is inside the measurement boundary.

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

mod rapidsnark;

#[cfg(all(feature = "passport-register", feature = "passport-disclose"))]
compile_error!("enable exactly one passport workload feature");
#[cfg(not(any(feature = "passport-register", feature = "passport-disclose")))]
compile_error!("enable one of passport-register or passport-disclose");

#[cfg(all(feature = "passport-register", not(target_os = "android")))]
const WORKLOAD: &str = "passport-register";
#[cfg(all(feature = "passport-disclose", not(target_os = "android")))]
const WORKLOAD: &str = "passport-disclose";

#[derive(Debug)]
pub struct PreparedProof {
    zkey_path: String,
    witness:   Vec<u8>,
}

#[derive(Debug)]
pub struct PreparedVerification {
    proof:            rapidsnark::ProofResult,
    verification_key: String,
}

#[derive(Debug)]
pub struct PreparedProofVerify {
    proof:            PreparedProof,
    verification_key: String,
}

fn fixture_root() -> PathBuf {
    if let Some(path) = env::var_os("MOBENCH_GROTH16_FIXTURE_ROOT") {
        return PathBuf::from(path);
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
        PathBuf::from(library_path)
            .parent()
            .expect("Android benchmark library has a parent")
            .to_path_buf()
    }

    #[cfg(not(target_os = "android"))]
    let executable = env::current_exe().expect("resolve benchmark executable path");
    #[cfg(not(target_os = "android"))]
    let bundle_root = executable
        .parent()
        .expect("benchmark executable has an app-bundle parent");
    #[cfg(not(target_os = "android"))]
    let nested = bundle_root.join("groth16").join(WORKLOAD);
    #[cfg(not(target_os = "android"))]
    if nested.join("proving_key.zkey").is_file() {
        nested
    } else {
        // Xcode's resources build phase flattens ordinary file references into
        // the application bundle root. Each workload is packaged as a separate
        // app, so these names remain unambiguous.
        bundle_root.to_path_buf()
    }
}

fn checked_fixture_file(root: &Path, name: &str) -> PathBuf {
    #[cfg(target_os = "android")]
    let packaged_name = match name {
        "proving_key.zkey" => "libmobench_proving_key.so",
        "reference.wtns" => "libmobench_reference_wtns.so",
        "verification_key.json" => "libmobench_verification_key.so",
        _ => name,
    };
    #[cfg(not(target_os = "android"))]
    let packaged_name = name;
    let path = root.join(packaged_name);
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

fn prove(prepared: PreparedProof) -> rapidsnark::ProofResult {
    rapidsnark::prove(&prepared.zkey_path, &prepared.witness)
        .expect("Rapidsnark Groth16 proof generation")
}

fn serialized_proof_size(proof: &rapidsnark::ProofResult) -> usize {
    format!(
        r#"{{"proof":{},"public_signals":{}}}"#,
        proof.proof, proof.public_signals
    )
    .len()
}

fn verification_key() -> String {
    let verification_key_path = checked_fixture_file(&fixture_root(), "verification_key.json");
    fs::read_to_string(&verification_key_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", verification_key_path.display()))
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
        let proof = prove(load_proof_fixture());
        assert!(
            rapidsnark::verify(&proof, &verification_key)
                .expect("verify valid Rapidsnark passport canary"),
            "valid Rapidsnark passport canary was rejected"
        );
        assert!(
            tampered_proof_is_rejected(proof, &verification_key),
            "tampered Rapidsnark passport canary was accepted"
        );
    });
}

fn setup_proof() -> PreparedProof {
    validation_gate();
    let root = fixture_root();
    let zkey_size = fs::metadata(checked_fixture_file(&root, "proving_key.zkey"))
        .expect("read passport zkey metadata")
        .len();
    let witness_size = fs::metadata(checked_fixture_file(&root, "reference.wtns"))
        .expect("read passport witness metadata")
        .len();
    mobench_sdk::record_run_u64("zkey_size_bytes", zkey_size);
    mobench_sdk::record_run_u64("witness_size_bytes", witness_size);
    mobench_sdk::record_run_u64(
        "proving_payload_size_bytes",
        zkey_size + witness_size,
    );
    load_proof_fixture()
}

fn setup_verification() -> PreparedVerification {
    validation_gate();
    let prepared = load_proof_fixture();
    let proof = rapidsnark::prove(&prepared.zkey_path, &prepared.witness)
        .expect("prepare verified Rapidsnark proof");
    let verification_key = verification_key();
    assert!(
        rapidsnark::verify(&proof, &verification_key).expect("verify prepared Rapidsnark proof"),
        "prepared Rapidsnark proof must verify"
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

#[benchmark(setup = setup_proof, per_iteration)]
pub fn bench_passport_rapidsnark_prove(prepared: PreparedProof) {
    let started = Instant::now();
    let proof = prove(prepared);
    let prove_time_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    mobench_sdk::record_sample_u64("prove_time_ns", prove_time_ns);
    mobench_sdk::record_sample_u64("proof_size_bytes", serialized_proof_size(&proof) as u64);
    black_box(proof);
}

#[benchmark(setup = setup_verification)]
pub fn bench_passport_rapidsnark_verify(prepared: &PreparedVerification) {
    let valid = rapidsnark::verify(&prepared.proof, &prepared.verification_key)
        .expect("Rapidsnark Groth16 verification");
    assert!(valid, "valid Rapidsnark proof was rejected");
    black_box(valid);
}

#[benchmark(setup = setup_proof_verify, per_iteration)]
pub fn bench_passport_rapidsnark_proof_verify(prepared: PreparedProofVerify) {
    let proof = prove(prepared.proof);
    let valid = rapidsnark::verify(&proof, &prepared.verification_key)
        .expect("Rapidsnark passport proof-and-verify");
    assert!(
        valid,
        "Rapidsnark passport proof-and-verify rejected its proof"
    );
    black_box((proof, valid));
}

uniffi::setup_scaffolding!();
mobench_sdk::export_native_c_abi!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_expected_mobench_functions() {
        let names = mobench_sdk::list_benchmark_names();
        eprintln!("registered benchmarks: {names:?}");
        assert!(
            names
                .iter()
                .any(|name| name.ends_with("::bench_passport_rapidsnark_prove")),
            "registered benchmarks: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|name| name.ends_with("::bench_passport_rapidsnark_verify")),
            "registered benchmarks: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|name| name.ends_with("::bench_passport_rapidsnark_proof_verify")),
            "registered benchmarks: {names:?}"
        );
    }

    #[test]
    fn frozen_fixture_proves_verifies_and_rejects_tampering() {
        validation_gate();
    }
}
