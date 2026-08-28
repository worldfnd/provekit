//! Native Mobench adapter for the Circom/Rapidsnark WebAuthn assertion lane.
//!
//! Input-to-proof functions generate a fresh WTNS from raw inputs and run
//! Rapidsnark in the same measured region. The frozen WTNS remains only as an
//! independently validated correctness canary.

use {
    libc::{c_char, c_void},
    memmap2::{Mmap, MmapOptions},
    mobench_sdk::benchmark,
    std::{
        env,
        ffi::{CStr, CString},
        fs::{self, File},
        hint::black_box,
        path::{Path, PathBuf},
        sync::Once,
        time::Instant,
    },
};

#[path = "../../rapidsnark-mobile/src/rapidsnark.rs"]
mod rapidsnark;

const INPUTS: &str =
    include_str!("../../circom/web/dist/assets/webauthn/webauthn_default.input.json");

pub struct PreparedProof {
    zkey_path: String,
    witness:   Mmap,
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

type GenerateWitness = unsafe extern "C" fn(*mut u8, usize) -> usize;

fn generate_witness() -> Vec<u8> {
    let root = fixture_root();
    let helper_path = checked_fixture_file(&root, "witness.so");
    let expected_size = fs::metadata(checked_fixture_file(&root, "reference.wtns"))
        .expect("read WebAuthn witness metadata")
        .len();
    let helper_path = CString::new(helper_path.to_string_lossy().as_bytes())
        .expect("witness helper path contains no NUL");
    let (handle, output, written) = std::thread::spawn(move || {
        // SAFETY: The path is a valid NUL-terminated string and Android's
        // dynamic linker owns the returned handle until the matching dlclose.
        let handle = unsafe {
            libc::dlopen(helper_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL)
        };
        assert!(!handle.is_null(), "load WebAuthn witness helper: {}", dl_error());
        let symbol = CString::new("mobench_generate_webauthn_witness")
            .expect("witness symbol contains no NUL");
        // SAFETY: `handle` is a live dlopen handle and the symbol name is valid.
        let address = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
        assert!(!address.is_null(), "resolve WebAuthn witness helper: {}", dl_error());
        // SAFETY: The helper exports exactly this C ABI function.
        let generate: GenerateWitness = unsafe { std::mem::transmute(address) };
        let mut output =
            vec![0_u8; usize::try_from(expected_size).expect("witness size fits usize")];
        // SAFETY: `output` is writable for its full length and the helper
        // checks the capacity before copying the generated WTNS.
        let written = unsafe { generate(output.as_mut_ptr(), output.len()) };
        // Keep the handle open: dlclose on a Rust cdylib can run its TLS
        // destructors on Android's benchmark thread. The caller releases the
        // large read-only image without invoking those destructors.
        (handle as usize, output, written)
    })
    .join()
    .expect("WebAuthn witness helper thread");
    release_helper_readonly_mapping(handle);
    assert_eq!(written, output.len(), "WebAuthn witness helper output length");
    output
}

fn release_helper_readonly_mapping(handle: usize) {
    // Keep the library loaded so its dynamic-loader/TLS bookkeeping remains
    // valid, but release the large first PT_LOAD (ELF headers + witness
    // tables) after generation. The first page contains the ELF header used by
    // loader diagnostics; the rest is immutable data no longer referenced.
    std::hint::black_box(handle);
    let maps = fs::read_to_string("/proc/self/maps").expect("read Android process maps");
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let range = match fields.next() {
            Some(value) => value,
            None => continue,
        };
        let permissions = match fields.next() {
            Some(value) => value,
            None => continue,
        };
        let offset = match fields.next() {
            Some(value) => value,
            None => continue,
        };
        let path = fields.last().unwrap_or_default();
        if !permissions.starts_with("r--")
            || offset != "00000000"
            || !path.ends_with("libmobench_witness.so")
        {
            continue;
        }
        let (start, end) = match range.split_once('-') {
            Some((start, end)) => (
                usize::from_str_radix(start, 16).ok(),
                usize::from_str_radix(end, 16).ok(),
            ),
            None => (None, None),
        };
        let (Some(start), Some(end)) = (start, end) else {
            continue;
        };
        let page = 4096_usize;
        let keep = start.saturating_add(page);
        if end <= keep {
            continue;
        }
        // SAFETY: This is the helper's private, file-backed read-only mapping;
        // witness generation has returned and no later benchmark code calls
        // into the helper. The first page remains mapped for loader metadata.
        let status = unsafe { libc::munmap(keep as *mut c_void, end - keep) };
        assert_eq!(status, 0, "release WebAuthn witness helper mapping");
        break;
    }
}

fn dl_error() -> String {
    // SAFETY: `dlerror` returns either a NUL-terminated diagnostic owned by
    // the dynamic linker or null; the string is copied before the next call.
    unsafe {
        let error = libc::dlerror();
        if error.is_null() {
            "unknown dynamic-loader error".to_owned()
        } else {
            CStr::from_ptr(error.cast::<c_char>())
                .to_string_lossy()
                .into_owned()
        }
    }
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
        return PathBuf::from(library_path)
            .parent()
            .expect("Android benchmark library has a parent")
            .to_path_buf();
    }

    #[cfg(not(target_os = "android"))]
    {
        env::current_exe()
            .expect("resolve benchmark executable path")
            .parent()
            .expect("benchmark executable has an app-bundle parent")
            .to_path_buf()
    }
}

fn checked_fixture_file(root: &Path, name: &str) -> PathBuf {
    #[cfg(target_os = "android")]
    let packaged_name = match name {
        "proving_key.zkey" => "libmobench_proving_key.so",
        "reference.wtns" => "libmobench_reference_wtns.so",
        "verification_key.json" => "libmobench_verification_key.so",
        "witness.so" => "libmobench_witness.so",
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
    let witness_file = File::open(&witness_path)
        .unwrap_or_else(|error| panic!("open {}: {error}", witness_path.display()));
    // SAFETY: The frozen witness file is immutable for the lifetime of each
    // benchmark process, and the mapping is retained in PreparedProof until
    // the native prover has finished reading it.
    let witness = unsafe { MmapOptions::new().map(&witness_file) }
        .unwrap_or_else(|error| panic!("mmap {}: {error}", witness_path.display()));
    PreparedProof {
        zkey_path: zkey.to_string_lossy().into_owned(),
        witness,
    }
}

fn prove(prepared: PreparedProof) -> rapidsnark::ProofResult {
    rapidsnark::prove(&prepared.zkey_path, &prepared.witness)
        .expect("Rapidsnark WebAuthn Groth16 proof")
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
            generated.as_slice(),
            frozen.witness.as_ref(),
            "live WebAuthn WTNS differs from frozen canary"
        );
        // The frozen witness is only an independently validated canary.  On
        // the 32-bit E15, retaining its mapping while Rapidsnark maps the
        // 1.73 GiB proving key exhausts the available address space.  Keep
        // the path, release the mapping, and prove from the live WTNS.
        let zkey_path = frozen.zkey_path.clone();
        drop(frozen);
        let proof = rapidsnark::prove(&zkey_path, &generated)
            .expect("Rapidsnark live WebAuthn canary");
        let proof_size_bytes = serialized_proof_size(&proof);
        assert!(
            rapidsnark::verify(&proof, &verification_key)
                .expect("verify valid Rapidsnark WebAuthn canary"),
            "valid Rapidsnark WebAuthn canary was rejected"
        );
        assert!(
            tampered_proof_is_rejected(proof, &verification_key),
            "tampered Rapidsnark WebAuthn canary was accepted"
        );
        let root = fixture_root();
        let zkey_size_bytes = fs::metadata(checked_fixture_file(&root, "proving_key.zkey"))
            .expect("read WebAuthn zkey metadata")
            .len();
        let witness_size_bytes = fs::metadata(checked_fixture_file(&root, "reference.wtns"))
            .expect("read WebAuthn witness metadata")
            .len();
        let verification_key_size_bytes =
            fs::metadata(checked_fixture_file(&root, "verification_key.json"))
                .expect("read WebAuthn verification-key metadata")
                .len();
        println!(
            "MOBENCH_METRIC_JSON {}",
            serde_json::json!({
                "schema_version": 1,
                "stack": "circom_rapidsnark",
                "workload": "webauthn",
                "proof_size_bytes": proof_size_bytes,
                "proving_payload": {
                    "zkey_size_bytes": zkey_size_bytes,
                    "witness_size_bytes": witness_size_bytes,
                    "verification_key_size_bytes": verification_key_size_bytes,
                    "deduplicated_total_bytes": zkey_size_bytes
                        + witness_size_bytes
                        + verification_key_size_bytes,
                },
                "tampered_proof_rejected": true,
                "timing_scope": "outside_measured_region",
            })
        );
    });
}

fn setup_input_to_proof() -> PreparedInputToProof {
    validation_gate();
    let zkey_path = checked_fixture_file(&fixture_root(), "proving_key.zkey");
    let zkey_size = fs::metadata(&zkey_path)
        .expect("read WebAuthn zkey metadata")
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

#[benchmark(setup = setup_input_to_proof, per_iteration)]
pub fn bench_webauthn_rapidsnark_input_to_proof(prepared: PreparedInputToProof) {
    let input_to_proof_started = Instant::now();
    let witness_started = Instant::now();
    let witness = generate_witness();
    let witness_time_ns = witness_started
        .elapsed()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    let prove_started = Instant::now();
    let proof = rapidsnark::prove(&prepared.zkey_path, &witness)
        .expect("Rapidsnark live-witness WebAuthn proof");
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
    let zkey_size_bytes = fs::metadata(checked_fixture_file(&root, "proving_key.zkey"))
        .expect("read WebAuthn zkey metadata")
        .len();
    let witness_size_bytes = fs::metadata(checked_fixture_file(&root, "reference.wtns"))
        .expect("read WebAuthn witness metadata")
        .len();
    mobench_sdk::record_run_u64("zkey_size_bytes", zkey_size_bytes);
    mobench_sdk::record_run_u64("witness_size_bytes", witness_size_bytes);
    mobench_sdk::record_run_u64(
        "proving_payload_size_bytes",
        zkey_size_bytes + witness_size_bytes,
    );
    load_proof_fixture()
}

fn verification_key() -> String {
    let path = checked_fixture_file(&fixture_root(), "verification_key.json");
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn setup_verification() -> PreparedVerification {
    validation_gate();
    let proof = prove(load_proof_fixture());
    let verification_key = verification_key();
    assert!(
        rapidsnark::verify(&proof, &verification_key)
            .expect("verify prepared Rapidsnark WebAuthn proof"),
        "prepared Rapidsnark WebAuthn proof must verify"
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
pub fn bench_webauthn_rapidsnark_prove(prepared: PreparedProof) {
    let started = Instant::now();
    let proof = prove(prepared);
    let prove_time_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    mobench_sdk::record_sample_u64("prove_time_ns", prove_time_ns);
    mobench_sdk::record_sample_u64("proof_size_bytes", serialized_proof_size(&proof) as u64);
    black_box(proof);
}

#[benchmark(setup = setup_verification)]
pub fn bench_webauthn_rapidsnark_verify(prepared: &PreparedVerification) {
    let valid = rapidsnark::verify(&prepared.proof, &prepared.verification_key)
        .expect("Rapidsnark WebAuthn verification");
    assert!(valid, "valid Rapidsnark WebAuthn proof was rejected");
    black_box(valid);
}

#[benchmark(setup = setup_proof_verify, per_iteration)]
pub fn bench_webauthn_rapidsnark_proof_verify(prepared: PreparedProofVerify) {
    let proof = prove(prepared.proof);
    let valid = rapidsnark::verify(&proof, &prepared.verification_key)
        .expect("Rapidsnark WebAuthn end-to-end verification");
    assert!(valid, "end-to-end Rapidsnark WebAuthn proof was rejected");
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
        for suffix in [
            "::bench_webauthn_rapidsnark_prove",
            "::bench_webauthn_rapidsnark_verify",
            "::bench_webauthn_rapidsnark_proof_verify",
        ] {
            assert!(
                names.iter().any(|name| name.ends_with(suffix)),
                "missing {suffix}: {names:?}"
            );
        }
    }

    #[test]
    fn frozen_fixture_proves_verifies_and_rejects_tampering() {
        validation_gate();
        let prepared = setup_verification();
        let proof_json = format!(
            r#"{{"proof":{},"public_signals":{}}}"#,
            prepared.proof.proof, prepared.proof.public_signals
        );
        eprintln!("RAPIDSNARK_WEBAUTHN_PROOF_JSON_BYTES={}", proof_json.len());
        if let Some(path) = env::var_os("MOBENCH_WEBAUTHN_PROOF_OUTPUT") {
            fs::write(path, proof_json).expect("write retained Rapidsnark proof");
        }
        assert!(
            rapidsnark::verify(&prepared.proof, &prepared.verification_key)
                .expect("verify valid proof")
        );
        assert!(tampered_proof_is_rejected(
            prepared.proof,
            &prepared.verification_key
        ));
    }
}
