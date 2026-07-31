use {
    crate::{
        initialize_local_crs, prove, verify, verify_package, verify_runtime_package, Workload,
    },
    std::{
        env, fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    },
};

const PACKAGE_ENV: &str = "MOBENCH_BB_V087_PACKAGE_ROOT";
const RUNTIME_MANIFEST: &str = "runtime-package-manifest.json";
static OUTPUT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct PreparedProof {
    circuit: PathBuf,
    witness: PathBuf,
    output:  PathBuf,
}

#[derive(Debug)]
pub struct PreparedVerification {
    public_inputs:    PathBuf,
    proof:            PathBuf,
    verification_key: PathBuf,
}

#[derive(Debug)]
pub struct PreparedEndToEnd {
    proof: PreparedProof,
}

fn benchmark_library_root() -> PathBuf {
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

fn encoded_resource_name(path: &Path) -> String {
    let encoded = path
        .to_string_lossy()
        .replace(['/', '.', '-'], "_")
        .replace("__", "_");
    format!("libmobench_bb_v087_{encoded}.so")
}

fn runtime_asset_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from(RUNTIME_MANIFEST),
        PathBuf::from("crs/bn254_g1.dat"),
        PathBuf::from("crs/bn254_g2.dat"),
    ];
    for workload in Workload::ALL {
        let root = Path::new("fixtures").join(workload.fixture_name());
        for name in [
            "circuit.json",
            "witness.gz",
            "public-inputs.json",
            "proof.bin",
            "bytecode.gz",
            "public_inputs",
        ] {
            paths.push(root.join(name));
        }
    }
    paths
}

fn materialize_embedded_package(source_root: &Path) -> PathBuf {
    let destination = env::temp_dir().join("provekit-v1-barretenberg-v087-runtime");
    for relative in runtime_asset_paths() {
        let source = source_root.join(encoded_resource_name(&relative));
        let target = destination.join(&relative);
        let bytes = fs::read(&source)
            .unwrap_or_else(|error| panic!("read embedded {}: {error}", source.display()));
        fs::create_dir_all(target.parent().expect("runtime asset has a parent"))
            .unwrap_or_else(|error| panic!("create runtime package directory: {error}"));
        fs::write(&target, bytes)
            .unwrap_or_else(|error| panic!("stage embedded {}: {error}", target.display()));
    }
    verify_runtime_package(&destination).expect("verify staged Barretenberg runtime package");
    destination
}

fn package_root() -> PathBuf {
    if let Some(path) = env::var_os(PACKAGE_ENV) {
        let root = PathBuf::from(path);
        if root.join(RUNTIME_MANIFEST).is_file() {
            verify_runtime_package(&root).expect("verify configured Barretenberg runtime package");
        } else {
            verify_package(&root).expect("verify configured Barretenberg full package");
        }
        return root;
    }

    let root = benchmark_library_root();
    let nested = root.join("barretenberg-v087");
    if nested.join(RUNTIME_MANIFEST).is_file() {
        verify_runtime_package(&nested).expect("verify bundled Barretenberg runtime package");
        return nested;
    }
    materialize_embedded_package(&root)
}

fn output_directory(workload: Workload) -> PathBuf {
    let sequence = OUTPUT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    env::temp_dir()
        .join("provekit-v1-barretenberg-v087-output")
        .join(format!(
            "{}-{}-{sequence}",
            workload.fixture_name(),
            std::process::id()
        ))
}

fn setup_proof(workload: Workload) -> PreparedProof {
    let root = package_root();
    initialize_local_crs(&root.join("crs")).expect("initialize exact v0.87 local CRS");
    let fixture = root.join("fixtures").join(workload.fixture_name());
    PreparedProof {
        circuit: fixture.join("bytecode.gz"),
        witness: fixture.join("witness.gz"),
        output:  output_directory(workload),
    }
}

pub fn run_proof(prepared: &PreparedProof) -> crate::ProofBundle {
    prove(&prepared.circuit, &prepared.witness, &prepared.output)
        .expect("Barretenberg v0.87 UltraHonk proof")
}

fn setup_verification(workload: Workload) -> PreparedVerification {
    let prepared = setup_proof(workload);
    let bundle = run_proof(&prepared);
    let verification = PreparedVerification {
        public_inputs:    prepared.output.join("public_inputs"),
        proof:            prepared.output.join("proof"),
        verification_key: prepared.output.join("vk"),
    };
    assert_eq!(
        bundle.proof,
        fs::read(&verification.proof).expect("read prepared proof"),
        "native returned proof differs from its output file"
    );
    assert!(
        verify(
            &verification.public_inputs,
            &verification.proof,
            &verification.verification_key
        )
        .expect("verify prepared Barretenberg proof"),
        "prepared Barretenberg proof must verify"
    );
    verification
}

fn setup_end_to_end(workload: Workload) -> PreparedEndToEnd {
    PreparedEndToEnd {
        proof: setup_proof(workload),
    }
}

pub fn run_verify(prepared: &PreparedVerification) -> bool {
    verify(
        &prepared.public_inputs,
        &prepared.proof,
        &prepared.verification_key,
    )
    .expect("Barretenberg v0.87 UltraHonk verification")
}

pub fn run_end_to_end(prepared: &PreparedEndToEnd) -> (crate::ProofBundle, bool) {
    let bundle = run_proof(&prepared.proof);
    let valid = verify(
        &prepared.proof.output.join("public_inputs"),
        &prepared.proof.output.join("proof"),
        &prepared.proof.output.join("vk"),
    )
    .expect("Barretenberg v0.87 end-to-end verification");
    assert!(valid, "end-to-end Barretenberg proof was rejected");
    (bundle, valid)
}

pub fn setup_passport_prove() -> PreparedProof {
    setup_proof(Workload::PassportCompleteAgeCheck)
}

pub fn setup_passport_verify() -> PreparedVerification {
    setup_verification(Workload::PassportCompleteAgeCheck)
}

pub fn setup_passport_e2e() -> PreparedEndToEnd {
    setup_end_to_end(Workload::PassportCompleteAgeCheck)
}

pub fn setup_webauthn_prove() -> PreparedProof {
    setup_proof(Workload::WebAuthnAssertion)
}

pub fn setup_webauthn_verify() -> PreparedVerification {
    setup_verification(Workload::WebAuthnAssertion)
}

pub fn setup_webauthn_e2e() -> PreparedEndToEnd {
    setup_end_to_end(Workload::WebAuthnAssertion)
}

pub fn setup_oprf_prove() -> PreparedProof {
    setup_proof(Workload::OprfTaceo)
}

pub fn setup_oprf_verify() -> PreparedVerification {
    setup_verification(Workload::OprfTaceo)
}

pub fn setup_oprf_e2e() -> PreparedEndToEnd {
    setup_end_to_end(Workload::OprfTaceo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_all_nine_mobench_functions() {
        let names = mobench_sdk::list_benchmark_names();
        for suffix in [
            "::bench_passport_barretenberg_prove",
            "::bench_passport_barretenberg_verify",
            "::bench_passport_barretenberg_e2e",
            "::bench_webauthn_barretenberg_prove",
            "::bench_webauthn_barretenberg_verify",
            "::bench_webauthn_barretenberg_e2e",
            "::bench_oprf_barretenberg_prove",
            "::bench_oprf_barretenberg_verify",
            "::bench_oprf_barretenberg_e2e",
        ] {
            assert!(
                names.iter().any(|name| name.ends_with(suffix)),
                "missing {suffix}: {names:?}"
            );
        }
    }

    #[test]
    fn frozen_oprf_proves_verifies_and_rejects_tampering() {
        let prepared = setup_verification(Workload::OprfTaceo);
        assert!(
            run_verify(&prepared),
            "valid frozen OPRF proof was rejected"
        );
        let mut proof = fs::read(&prepared.proof).expect("read OPRF proof");
        let midpoint = proof.len() / 2;
        proof[midpoint] ^= 1;
        fs::write(&prepared.proof, proof).expect("write tampered OPRF proof");
        assert!(
            !run_verify(&prepared),
            "one-bit-tampered OPRF proof was accepted"
        );
    }
}
