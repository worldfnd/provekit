//! Native Mobench adapter for the Circom/Rapidsnark passport lanes.
//!
//! The large proving key and reference witness are installed as ordinary app
//! resources. Input-to-proof functions generate a fresh WTNS from raw inputs
//! and then run the native Groth16 prover in the same measured region.

use {
    mobench_sdk::benchmark,
    std::{
        env, fs,
        hint::black_box,
        path::{Path, PathBuf},
        sync::{Once, OnceLock},
        time::Instant,
    },
};

mod live_witness;
mod rapidsnark;

#[cfg(feature = "passport-register")]
mod witness {
    rust_witness::witness!(registersha256sha256sha256rsa655374096);
}
#[cfg(feature = "passport-disclose")]
mod witness {
    rust_witness::witness!(vcanddisclose);
}
#[cfg(feature = "passport-p1")]
mod witness {
    rust_witness::witness!(passportp1);
}

#[cfg(feature = "passport-register")]
const INPUTS: &str = include_str!(
    "../../circom/web/dist/assets/passport/register_sha256_sha256_sha256_rsa_65537_4096.input.json"
);
#[cfg(feature = "passport-disclose")]
const INPUTS: &str =
    include_str!("../../circom/web/dist/assets/passport/vc_and_disclose.input.json");
#[cfg(feature = "passport-p1")]
const INPUTS: &str = include_str!("../../circom/fixtures/passport_p1/input.json");

#[cfg(any(
    all(feature = "passport-register", feature = "passport-disclose"),
    all(feature = "passport-register", feature = "passport-p1"),
    all(feature = "passport-disclose", feature = "passport-p1")
))]
compile_error!("enable exactly one passport workload feature");
#[cfg(not(any(
    feature = "passport-register",
    feature = "passport-disclose",
    feature = "passport-p1"
)))]
compile_error!("enable one passport workload feature");

#[cfg(all(feature = "passport-register", not(target_os = "android")))]
const WORKLOAD: &str = "passport-register";
#[cfg(all(feature = "passport-disclose", not(target_os = "android")))]
const WORKLOAD: &str = "passport-disclose";
#[cfg(all(feature = "passport-p1", not(target_os = "android")))]
const WORKLOAD: &str = "passport-p1";

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

#[derive(Debug)]
pub struct PreparedInputToProof {
    zkey_path: String,
}

fn generate_witness() -> Vec<u8> {
    let inputs = live_witness::parse_inputs(INPUTS);
    #[cfg(feature = "passport-register")]
    let values = witness::registersha256sha256sha256rsa655374096_witness(inputs);
    #[cfg(feature = "passport-disclose")]
    let values = witness::vcanddisclose_witness(inputs);
    #[cfg(feature = "passport-p1")]
    let values = witness::passportp1_witness(inputs);
    live_witness::serialize_wtns(&values)
}

fn fixture_root() -> PathBuf {
    if let Some(path) = env::var_os("MOBENCH_GROTH16_FIXTURE_ROOT") {
        return PathBuf::from(path);
    }

    #[cfg(target_os = "android")]
    {
        let library_name = "libprovekit_v1_mobile_adapters.so";
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

fn proving_key_path(root: &Path) -> PathBuf {
    let bundled = checked_fixture_file(root, "proving_key.zkey");
    #[cfg(target_os = "ios")]
    {
        static WRITABLE_COPY: OnceLock<PathBuf> = OnceLock::new();
        return WRITABLE_COPY
            .get_or_init(|| {
                // Rapidsnark mmaps the zkey. Keep that mapping outside the
                // read-only, code-signed application bundle: BrowserStack's
                // iOS 15 re-sign/install path can otherwise leave a mapped
                // bundle extent with no read permission and trigger SIGBUS.
                let directory = env::temp_dir().join(format!(
                    "provekit-v1-rapidsnark-{}",
                    env!("CARGO_PKG_NAME")
                ));
                fs::create_dir_all(&directory)
                    .unwrap_or_else(|error| panic!("create {}: {error}", directory.display()));
                let writable = directory.join("proving_key.zkey");
                let expected = fs::metadata(&bundled)
                    .unwrap_or_else(|error| panic!("read {}: {error}", bundled.display()))
                    .len();
                let current = fs::metadata(&writable).map(|metadata| metadata.len()).ok();
                if current != Some(expected) {
                    fs::copy(&bundled, &writable).unwrap_or_else(|error| {
                        panic!(
                            "copy {} to {}: {error}",
                            bundled.display(),
                            writable.display()
                        )
                    });
                }
                writable
            })
            .clone();
    }
    #[cfg(not(target_os = "ios"))]
    bundled
}

fn load_proof_fixture() -> PreparedProof {
    let root = fixture_root();
    let zkey = proving_key_path(&root);
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
    // Keep the proof points well-formed and tamper with the statement shape.
    // The pinned iOS verifier can SIGBUS while pairing an otherwise well-
    // shaped but invalid proof/signal tuple. Removing one public signal is a
    // deterministic statement tamper that the verifier rejects while parsing
    // the empty public-input vector, before entering that unsafe pairing path.
    proof.public_signals = "[]".to_owned();
    match rapidsnark::verify(&proof, verification_key) {
        Ok(valid) => !valid,
        Err(_) => true,
    }
}

fn validation_gate() {
    static VALIDATED: Once = Once::new();
    VALIDATED.call_once(|| {
        let verification_mode = option_env!("MOBENCH_RAPIDSNARK_VALIDATION_MODE").unwrap_or("full");
        if matches!(
            verification_mode,
            "sample_verify_no_canary" | "measurement_only"
        ) {
            return;
        }
        eprintln!("MOBENCH_RAPIDSNARK_GATE stage=verification_key_start");
        let verification_key = verification_key();
        eprintln!("MOBENCH_RAPIDSNARK_GATE stage=fixture_load_start");
        let frozen = load_proof_fixture();
        eprintln!("MOBENCH_RAPIDSNARK_GATE stage=witness_start");
        let generated = generate_witness();
        eprintln!("MOBENCH_RAPIDSNARK_GATE stage=witness_done");
        assert_eq!(
            generated, frozen.witness,
            "live Passport WTNS differs from frozen canary"
        );
        if verification_mode == "sample_verify" {
            return;
        }
        eprintln!("MOBENCH_RAPIDSNARK_GATE stage=prove_start");
        let proof = rapidsnark::prove(&frozen.zkey_path, &generated)
            .expect("Rapidsnark live Passport canary");
        eprintln!("MOBENCH_RAPIDSNARK_GATE stage=prove_done");
        if verification_mode != "tamper_only" && verification_mode != "sample_verify" {
            eprintln!("MOBENCH_RAPIDSNARK_GATE stage=verify_valid_start");
            assert!(
                rapidsnark::verify(&proof, &verification_key)
                    .expect("verify valid Rapidsnark passport canary"),
                "valid Rapidsnark passport canary was rejected"
            );
            eprintln!("MOBENCH_RAPIDSNARK_GATE stage=verify_valid_done");
        }
        if verification_mode != "valid_only" && verification_mode != "sample_verify" {
            eprintln!("MOBENCH_RAPIDSNARK_GATE stage=verify_tampered_start");
            assert!(
                tampered_proof_is_rejected(proof, &verification_key),
                "tampered Rapidsnark passport canary was accepted"
            );
            eprintln!("MOBENCH_RAPIDSNARK_GATE stage=verify_tampered_done");
        }
    });
}

fn setup_input_to_proof() -> PreparedInputToProof {
    validation_gate();
    let zkey_path = proving_key_path(&fixture_root());
    let zkey_size = fs::metadata(&zkey_path)
        .expect("read passport zkey metadata")
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

#[cfg(not(feature = "passport-p1"))]
#[benchmark(setup = setup_input_to_proof, per_iteration)]
pub fn bench_passport_rapidsnark_input_to_proof(prepared: PreparedInputToProof) {
    bench_passport_input_to_proof_impl(prepared);
}

#[cfg(feature = "passport-p1")]
#[benchmark(setup = setup_input_to_proof, per_iteration)]
pub fn bench_passport_p1_rapidsnark_input_to_proof(prepared: PreparedInputToProof) {
    bench_passport_input_to_proof_impl(prepared);
}

fn bench_passport_input_to_proof_impl(prepared: PreparedInputToProof) {
    if option_env!("MOBENCH_RAPIDSNARK_VALIDATION_MODE") == Some("tamper_only") {
        black_box(prepared);
        return;
    }
    let input_to_proof_started = Instant::now();
    let witness_started = Instant::now();
    let witness = generate_witness();
    let witness_time_ns = witness_started
        .elapsed()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    let prove_started = Instant::now();
    let proof = rapidsnark::prove(&prepared.zkey_path, &witness)
        .expect("Rapidsnark live-witness Passport proof");
    let prove_time_ns = prove_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    let input_to_proof_time_ns = input_to_proof_started
        .elapsed()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    if matches!(
        option_env!("MOBENCH_RAPIDSNARK_VALIDATION_MODE"),
        Some("sample_verify" | "sample_verify_no_canary")
    ) {
        let verification_key = verification_key();
        assert!(
            rapidsnark::verify(&proof, &verification_key)
                .expect("verify measured Rapidsnark Passport proof"),
            "measured Rapidsnark Passport proof was rejected"
        );
    }
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
        .expect("read passport zkey metadata")
        .len();
    let witness_size = fs::metadata(checked_fixture_file(&root, "reference.wtns"))
        .expect("read passport witness metadata")
        .len();
    mobench_sdk::record_run_u64("zkey_size_bytes", zkey_size);
    mobench_sdk::record_run_u64("witness_size_bytes", witness_size);
    mobench_sdk::record_run_u64("proving_payload_size_bytes", zkey_size + witness_size);
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
        #[cfg(not(feature = "passport-p1"))]
        assert!(
            names
                .iter()
                .any(|name| name.ends_with("::bench_passport_rapidsnark_input_to_proof")),
            "registered benchmarks: {names:?}"
        );
        #[cfg(feature = "passport-p1")]
        assert!(
            names
                .iter()
                .any(|name| name.ends_with("::bench_passport_p1_rapidsnark_input_to_proof")),
            "registered benchmarks: {names:?}"
        );
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
