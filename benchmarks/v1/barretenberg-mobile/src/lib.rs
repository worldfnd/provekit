//! Fail-closed Rust boundary for exact Noir beta.11 / Barretenberg v0.87.

mod manifest;
mod phases;

#[cfg(all(feature = "mobench", feature = "native-v087"))]
mod mobench;

#[cfg(all(feature = "mobench", feature = "native-v087"))]
mod native_c_abi;

#[cfg(all(feature = "mobench", feature = "native-v087"))]
use {
    mobench::{
        setup_oprf_e2e, setup_oprf_prove, setup_oprf_verify, setup_passport_e2e,
        setup_passport_prove, setup_passport_verify, setup_webauthn_e2e, setup_webauthn_prove,
        setup_webauthn_verify,
    },
    mobench_sdk::benchmark,
    std::hint::black_box,
};

#[cfg(all(
    feature = "native-v087",
    not(all(target_os = "ios", target_abi = "sim"))
))]
mod native;

#[cfg(all(feature = "native-v087", target_os = "ios", target_abi = "sim"))]
#[path = "native_ios_sim.rs"]
mod native;

#[cfg(feature = "native-v087")]
pub use native::{initialize_local_crs, prove, verify, ProofBundle};
pub use {
    manifest::{verify_package, verify_runtime_package, PackageManifest, VerifiedPackage},
    phases::{Backend, Phase, Workload},
};

/// Returns the reason this build cannot execute native v0.87.
pub fn unavailable_reason() -> Option<&'static str> {
    #[cfg(feature = "native-v087")]
    {
        None
    }
    #[cfg(not(feature = "native-v087"))]
    {
        Some(
            "exact Barretenberg v0.87 native archive is not linked; build with native-v087 and \
             BB_V087_MOBILE_LIB_DIR",
        )
    }
}

#[cfg(all(feature = "mobench", feature = "native-v087"))]
#[benchmark(setup = setup_passport_prove, per_iteration)]
pub fn bench_passport_barretenberg_prove(prepared: mobench::PreparedProof) {
    black_box(mobench::run_proof(&prepared));
}

#[cfg(all(feature = "mobench", feature = "native-v087"))]
#[benchmark(setup = setup_passport_verify)]
pub fn bench_passport_barretenberg_verify(prepared: &mobench::PreparedVerification) {
    let valid = mobench::run_verify(prepared);
    assert!(valid, "valid Passport Barretenberg proof was rejected");
    black_box(valid);
}

#[cfg(all(feature = "mobench", feature = "native-v087"))]
#[benchmark(setup = setup_passport_e2e, per_iteration)]
pub fn bench_passport_barretenberg_e2e(prepared: mobench::PreparedEndToEnd) {
    black_box(mobench::run_end_to_end(&prepared));
}

#[cfg(all(feature = "mobench", feature = "native-v087"))]
#[benchmark(setup = setup_webauthn_prove, per_iteration)]
pub fn bench_webauthn_barretenberg_prove(prepared: mobench::PreparedProof) {
    black_box(mobench::run_proof(&prepared));
}

#[cfg(all(feature = "mobench", feature = "native-v087"))]
#[benchmark(setup = setup_webauthn_verify)]
pub fn bench_webauthn_barretenberg_verify(prepared: &mobench::PreparedVerification) {
    let valid = mobench::run_verify(prepared);
    assert!(valid, "valid WebAuthn Barretenberg proof was rejected");
    black_box(valid);
}

#[cfg(all(feature = "mobench", feature = "native-v087"))]
#[benchmark(setup = setup_webauthn_e2e, per_iteration)]
pub fn bench_webauthn_barretenberg_e2e(prepared: mobench::PreparedEndToEnd) {
    black_box(mobench::run_end_to_end(&prepared));
}

#[cfg(all(feature = "mobench", feature = "native-v087"))]
#[benchmark(setup = setup_oprf_prove, per_iteration)]
pub fn bench_oprf_barretenberg_prove(prepared: mobench::PreparedProof) {
    black_box(mobench::run_proof(&prepared));
}

#[cfg(all(feature = "mobench", feature = "native-v087"))]
#[benchmark(setup = setup_oprf_verify)]
pub fn bench_oprf_barretenberg_verify(prepared: &mobench::PreparedVerification) {
    let valid = mobench::run_verify(prepared);
    assert!(valid, "valid OPRF Barretenberg proof was rejected");
    black_box(valid);
}

#[cfg(all(feature = "mobench", feature = "native-v087"))]
#[benchmark(setup = setup_oprf_e2e, per_iteration)]
pub fn bench_oprf_barretenberg_e2e(prepared: mobench::PreparedEndToEnd) {
    black_box(mobench::run_end_to_end(&prepared));
}

#[cfg(all(feature = "mobench", feature = "native-v087"))]
uniffi::setup_scaffolding!();
