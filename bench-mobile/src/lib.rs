//! Mobile benchmarks for ProveKit passport and example circuits.

use {
    crate::passport::{
        prove_complete_age_check_fixture, prove_complete_age_check_fixture_proof_only,
        prove_fragmented_age_check_fixture_proof_only, verify_complete_age_check_fixture,
        PreparedCompleteAgeCheckFixture, PreparedCompleteAgeCheckProver,
        PreparedCompleteAgeCheckProverWithSerializedVerifier, PreparedFragmentedAgeCheckProvers,
        VerifiedCompleteAgeCheckFixture,
    },
    examples::{
        MobileBenchFixture, PreparedCircuitFixture, PreparedProverFixture, VerifiedCircuitFixture,
    },
    mobench_sdk::{benchmark, profile_phase},
    provekit_common::{file::serialize, NoirProof},
    serde_json::json,
    std::{
        hint::black_box,
        sync::{Once, OnceLock},
        time::Instant,
    },
};

pub mod examples;
mod in_process;
pub mod passport;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BenchSpec {
    pub name:       String,
    pub iterations: u32,
    pub warmup:     u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BenchSample {
    pub duration_ns:            u64,
    pub cpu_time_ms:            Option<u64>,
    pub peak_memory_kb:         Option<u64>,
    pub process_peak_memory_kb: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SemanticPhase {
    pub name:        String,
    pub duration_ns: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HarnessTimelineSpan {
    pub phase:           String,
    pub start_offset_ns: u64,
    pub end_offset_ns:   u64,
    pub iteration:       Option<u32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BenchReport {
    pub spec:     BenchSpec,
    pub samples:  Vec<BenchSample>,
    pub phases:   Vec<SemanticPhase>,
    pub timeline: Vec<HarnessTimelineSpan>,
}

#[derive(Debug, thiserror::Error)]
pub enum BenchError {
    #[error("iterations must be greater than zero")]
    InvalidIterations,

    #[error("unknown benchmark function: {name}")]
    UnknownFunction { name: String },

    #[error("benchmark execution failed: {reason}")]
    ExecutionFailed { reason: String },
}

impl From<mobench_sdk::BenchSpec> for BenchSpec {
    fn from(spec: mobench_sdk::BenchSpec) -> Self {
        Self {
            name:       spec.name,
            iterations: spec.iterations,
            warmup:     spec.warmup,
        }
    }
}

impl From<BenchSpec> for mobench_sdk::BenchSpec {
    fn from(spec: BenchSpec) -> Self {
        Self {
            name:       spec.name,
            iterations: spec.iterations,
            warmup:     spec.warmup,
        }
    }
}

impl From<mobench_sdk::BenchSample> for BenchSample {
    fn from(sample: mobench_sdk::BenchSample) -> Self {
        Self {
            duration_ns:            sample.duration_ns,
            cpu_time_ms:            sample.cpu_time_ms,
            peak_memory_kb:         sample.peak_memory_kb,
            process_peak_memory_kb: sample.process_peak_memory_kb,
        }
    }
}

impl From<mobench_sdk::SemanticPhase> for SemanticPhase {
    fn from(phase: mobench_sdk::SemanticPhase) -> Self {
        Self {
            name:        phase.name,
            duration_ns: phase.duration_ns,
        }
    }
}

impl From<mobench_sdk::HarnessTimelineSpan> for HarnessTimelineSpan {
    fn from(span: mobench_sdk::HarnessTimelineSpan) -> Self {
        Self {
            phase:           span.phase,
            start_offset_ns: span.start_offset_ns,
            end_offset_ns:   span.end_offset_ns,
            iteration:       span.iteration,
        }
    }
}

impl From<mobench_sdk::RunnerReport> for BenchReport {
    fn from(report: mobench_sdk::RunnerReport) -> Self {
        Self {
            spec:     report.spec.into(),
            samples:  report.samples.into_iter().map(Into::into).collect(),
            phases:   report.phases.into_iter().map(Into::into).collect(),
            timeline: report.timeline.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<mobench_sdk::BenchError> for BenchError {
    fn from(err: mobench_sdk::BenchError) -> Self {
        match err {
            mobench_sdk::BenchError::Runner(runner_err) => Self::ExecutionFailed {
                reason: runner_err.to_string(),
            },
            mobench_sdk::BenchError::UnknownFunction(name, _available) => {
                Self::UnknownFunction { name }
            }
            _ => Self::ExecutionFailed {
                reason: err.to_string(),
            },
        }
    }
}

fn log_benchmark_lifecycle(
    event: &str,
    function: &str,
    iterations: u32,
    warmup: u32,
    extra: serde_json::Value,
) {
    let payload = json!({
        "tag": "MOBENCH_LIFECYCLE",
        "event": event,
        "function": function,
        "iterations": iterations,
        "warmup": warmup,
        "extra": extra,
    });

    if event == "error" {
        eprintln!("{payload}");
    } else {
        println!("{payload}");
    }
}

fn benchmark_start_metadata(function: &str) -> serde_json::Value {
    // Querying outside a Rayon worker lazily initializes the normal global
    // pool when needed; it does not configure or constrain the worker count.
    json!({
        "resolved_function": function,
        "rayon_threads": rayon::current_num_threads(),
    })
}

pub fn run_benchmark(spec: BenchSpec) -> Result<BenchReport, BenchError> {
    let function = spec.name.clone();
    let iterations = spec.iterations;
    let warmup = spec.warmup;
    log_benchmark_lifecycle(
        "start",
        &function,
        iterations,
        warmup,
        benchmark_start_metadata(&function),
    );

    let sdk_spec: mobench_sdk::BenchSpec = spec.into();
    match mobench_sdk::run_benchmark(sdk_spec) {
        Ok(report) => {
            log_benchmark_lifecycle(
                "success",
                &report.spec.name,
                report.spec.iterations,
                report.spec.warmup,
                json!({
                    "sample_count": report.samples.len(),
                    "phase_count": report.phases.len(),
                    "timeline_span_count": report.timeline.len(),
                    "sample_resource_count": report
                        .samples
                        .iter()
                        .filter(|sample| {
                            sample.cpu_time_ms.is_some()
                                || sample.peak_memory_kb.is_some()
                                || sample.process_peak_memory_kb.is_some()
                        })
                        .count(),
                }),
            );
            Ok(report.into())
        }
        Err(err) => {
            log_benchmark_lifecycle(
                "error",
                &function,
                iterations,
                warmup,
                json!({
                    "resolved_function": function,
                    "error": err.to_string(),
                }),
            );
            Err(err.into())
        }
    }
}

mobench_sdk::export_native_c_abi!();

fn setup_complete_age_check_prepared() -> PreparedCompleteAgeCheckFixture {
    let prepared =
        passport::prepare_complete_age_check_fixture().expect("prepare complete_age_check fixture");
    in_process::trim_process_memory();
    prepared
}

fn setup_complete_age_check_verified() -> VerifiedCompleteAgeCheckFixture {
    let prepared = setup_complete_age_check_prepared();
    let verified =
        prove_complete_age_check_fixture(prepared).expect("prove complete_age_check fixture");
    in_process::trim_process_memory();
    verified
}

fn setup_complete_age_check_prover() -> PreparedCompleteAgeCheckProver {
    static VALIDATION_GATE: Once = Once::new();
    VALIDATION_GATE.call_once(|| {
        let prepared = passport::prepare_complete_age_check_fixture()
            .expect("prepare complete_age_check validation canary");
        let verified = prove_complete_age_check_fixture(prepared)
            .expect("prove complete_age_check validation canary");
        verified
            .verify_and_reject_tampered()
            .expect("validate complete_age_check proof and tamper rejection");
    });
    let prover = passport::prepare_complete_age_check_fixture()
        .expect("prepare complete_age_check fixture")
        .into_prover_only();
    record_proving_payload(&prover);
    in_process::trim_process_memory();
    prover
}

fn passport_single_thread_pool() -> &'static rayon::ThreadPool {
    static SINGLE_THREAD_POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    SINGLE_THREAD_POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("build single-thread Passport pool")
    })
}

fn setup_complete_age_check_prover_single_thread(
) -> PreparedCompleteAgeCheckProverWithSerializedVerifier {
    in_process::log_process_memory("before_frozen_prover_load");
    let frozen = passport::frozen_complete_age_check_fixture();
    let (prover_size_bytes, input_size_bytes) = frozen.proving_payload_sizes();
    let prover = frozen
        .load_prover_with_serialized_verifier()
        .expect("load frozen single-thread complete_age_check prover");
    record_proving_payload_sizes(prover_size_bytes, input_size_bytes);
    in_process::log_process_memory("after_frozen_prover_load");
    in_process::trim_process_memory();
    let memory = in_process::log_process_memory("after_setup_trim");
    mobench_sdk::record_run_u64("passport_setup_rss_kb", memory.rss_kb);
    mobench_sdk::record_run_u64("passport_setup_swap_kb", memory.swap_kb);
    prover
}

fn setup_fragmented_age_check_provers() -> PreparedFragmentedAgeCheckProvers {
    let provers = passport::prepare_fragmented_age_check_fixture()
        .expect("prepare fragmented age_check fixture")
        .into_provers();
    in_process::trim_process_memory();
    provers
}

fn setup_oprf_prepared() -> PreparedCircuitFixture {
    let prepared =
        examples::prepare_fixture(MobileBenchFixture::Oprf).expect("prepare oprf fixture");
    in_process::trim_process_memory();
    prepared
}

fn setup_oprf_verified() -> VerifiedCircuitFixture {
    let prepared = setup_oprf_prepared();
    let verified = examples::prove_fixture(prepared).expect("prove oprf fixture");
    in_process::trim_process_memory();
    verified
}

fn setup_oprf_prover() -> PreparedProverFixture {
    static VALIDATION_GATE: Once = Once::new();
    VALIDATION_GATE.call_once(|| {
        let prepared = examples::prepare_fixture(MobileBenchFixture::Oprf)
            .expect("prepare oprf validation canary");
        let verified = examples::prove_fixture(prepared).expect("prove oprf validation canary");
        verified
            .verify_and_reject_tampered()
            .expect("validate oprf proof and tamper rejection");
    });
    let prover = examples::prepare_fixture(MobileBenchFixture::Oprf)
        .expect("prepare oprf fixture")
        .into_prover_only();
    record_proving_payload(&prover);
    in_process::trim_process_memory();
    prover
}

fn setup_p256_bigcurve_prepared() -> PreparedCircuitFixture {
    let prepared = examples::prepare_fixture(MobileBenchFixture::P256Bigcurve)
        .expect("prepare p256_bigcurve fixture");
    in_process::trim_process_memory();
    prepared
}

fn setup_p256_bigcurve_verified() -> VerifiedCircuitFixture {
    let prepared = setup_p256_bigcurve_prepared();
    let verified = examples::prove_fixture(prepared).expect("prove p256_bigcurve fixture");
    in_process::trim_process_memory();
    verified
}

fn setup_p256_bigcurve_prover() -> PreparedProverFixture {
    let prover = examples::prepare_fixture(MobileBenchFixture::P256Bigcurve)
        .expect("prepare p256_bigcurve fixture")
        .into_prover_only();
    in_process::trim_process_memory();
    prover
}

fn setup_webauthn_assertion_prepared() -> PreparedCircuitFixture {
    let prepared = examples::prepare_fixture(MobileBenchFixture::WebauthnAssertion)
        .expect("prepare webauthn_assertion fixture");
    in_process::trim_process_memory();
    prepared
}

fn setup_webauthn_assertion_verified() -> VerifiedCircuitFixture {
    let prepared = setup_webauthn_assertion_prepared();
    let verified = examples::prove_fixture(prepared).expect("prove webauthn_assertion fixture");
    in_process::trim_process_memory();
    verified
}

fn setup_webauthn_assertion_prover() -> PreparedProverFixture {
    static VALIDATION_GATE: Once = Once::new();
    VALIDATION_GATE.call_once(|| {
        let prepared = examples::prepare_fixture(MobileBenchFixture::WebauthnAssertion)
            .expect("prepare webauthn_assertion validation canary");
        let verified =
            examples::prove_fixture(prepared).expect("prove webauthn_assertion validation canary");
        verified
            .verify_and_reject_tampered()
            .expect("validate webauthn_assertion proof and tamper rejection");
    });
    let prover = examples::prepare_fixture(MobileBenchFixture::WebauthnAssertion)
        .expect("prepare webauthn_assertion fixture")
        .into_prover_only();
    record_proving_payload(&prover);
    in_process::trim_process_memory();
    prover
}

fn record_proving_payload(prover: &PreparedProverFixture) {
    let (prover_size_bytes, input_size_bytes) = prover
        .proving_payload_sizes()
        .expect("serialize ProveKit proving payload");
    record_proving_payload_sizes(prover_size_bytes, input_size_bytes);
}

fn record_proving_payload_sizes(prover_size_bytes: usize, input_size_bytes: usize) {
    mobench_sdk::record_run_u64("prover_size_bytes", prover_size_bytes as u64);
    mobench_sdk::record_run_u64("input_size_bytes", input_size_bytes as u64);
    mobench_sdk::record_run_u64(
        "proving_payload_size_bytes",
        (prover_size_bytes + input_size_bytes) as u64,
    );
}

fn record_proof_metrics(proof: &NoirProof, prove_started: Instant) {
    let (prove_time_ns, proof_size_bytes) = exact_proof_metrics(proof, prove_started);
    mobench_sdk::record_sample_u64("prove_time_ns", prove_time_ns);
    mobench_sdk::record_sample_u64("proof_size_bytes", proof_size_bytes);
}

fn exact_proof_metrics(proof: &NoirProof, prove_started: Instant) -> (u64, u64) {
    let prove_time_ns = prove_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    let proof_size_bytes = serialize(proof)
        .expect("serialize exact ProveKit .np proof")
        .len() as u64;
    (prove_time_ns, proof_size_bytes)
}

#[benchmark]
pub fn bench_passport_complete_age_check_prepare() {
    let prepared = profile_phase("prepare", || {
        passport::prepare_complete_age_check_fixture().expect("prepare complete_age_check fixture")
    });

    black_box((
        prepared.prover_size(),
        prepared.constraint_count(),
        prepared.input_count(),
    ));
}

#[benchmark(setup = setup_complete_age_check_prover, per_iteration)]
pub fn bench_passport_complete_age_check_prove(prepared: PreparedCompleteAgeCheckProver) {
    let prove_started = Instant::now();
    let proof = profile_phase("prove", || {
        prove_complete_age_check_fixture_proof_only(prepared)
            .expect("prove complete_age_check fixture")
    });

    record_proof_metrics(&proof, prove_started);
    black_box(proof);
}

/// Memory-constrained proof-only Passport lane for 32-bit Android devices.
///
/// Both the correctness canary and every timed proof execute inside the same
/// one-thread Rayon pool. This preserves the proof-only timing and exact proof
/// metrics while preventing parallel proof phases from exhausting low-memory
/// devices.
#[benchmark(setup = setup_complete_age_check_prover_single_thread, per_iteration)]
pub fn bench_passport_complete_age_check_prove_single_thread(
    prepared: PreparedCompleteAgeCheckProverWithSerializedVerifier,
) {
    let (prove_time_ns, proof_size_bytes, after_prove, before_verify, after_verify) =
        passport_single_thread_pool().install(|| {
            let prove_started = Instant::now();
            let verified = profile_phase("prove", || {
                prepared
                    .prove()
                    .expect("prove single-thread complete_age_check fixture")
            });

            let proof_metrics = exact_proof_metrics(verified.proof(), prove_started);
            let after_prove = in_process::log_process_memory("after_prove");
            in_process::trim_process_memory();
            let before_verify = in_process::log_process_memory("after_prove_trim");
            verified
                .verify_and_reject_tampered()
                .expect("verify single-thread complete_age_check proof and reject tampering");
            let after_verify = in_process::log_process_memory("after_verify");
            (
                proof_metrics.0,
                proof_metrics.1,
                after_prove,
                before_verify,
                after_verify,
            )
        });
    mobench_sdk::record_sample_u64("prove_time_ns", prove_time_ns);
    mobench_sdk::record_sample_u64("proof_size_bytes", proof_size_bytes);
    mobench_sdk::record_sample_u64("rss_after_prove_kb", after_prove.rss_kb);
    mobench_sdk::record_sample_u64("swap_after_prove_kb", after_prove.swap_kb);
    mobench_sdk::record_sample_u64("rss_before_verify_kb", before_verify.rss_kb);
    mobench_sdk::record_sample_u64("swap_before_verify_kb", before_verify.swap_kb);
    mobench_sdk::record_sample_u64("rss_after_verify_kb", after_verify.rss_kb);
    mobench_sdk::record_sample_u64("swap_after_verify_kb", after_verify.swap_kb);
}

#[benchmark(setup = setup_complete_age_check_verified)]
pub fn bench_passport_complete_age_check_verify(verified: &VerifiedCompleteAgeCheckFixture) {
    let verified = profile_phase("verify", || {
        verify_complete_age_check_fixture(verified.clone())
            .expect("verify complete_age_check fixture")
    });

    black_box(verified);
}

fn run_passport_complete_age_check_e2e() {
    static VALIDATION_GATE: Once = Once::new();
    VALIDATION_GATE.call_once(|| {
        let prepared = passport::prepare_complete_age_check_fixture()
            .expect("prepare complete_age_check validation canary");
        let verified = prove_complete_age_check_fixture(prepared)
            .expect("prove complete_age_check validation canary");
        verified
            .verify_and_reject_tampered()
            .expect("validate complete_age_check proof and tamper rejection");
    });

    let prepared = profile_phase("prepare", || {
        passport::prepare_complete_age_check_fixture().expect("prepare complete_age_check fixture")
    });
    let verified = profile_phase("prove", || {
        prove_complete_age_check_fixture(prepared).expect("prove complete_age_check fixture")
    });
    let verified = profile_phase("verify", || {
        verify_complete_age_check_fixture(verified).expect("verify complete_age_check fixture")
    });

    black_box(verified);
}

#[benchmark]
pub fn bench_passport_complete_age_check_e2e() {
    run_passport_complete_age_check_e2e();
}

/// Memory-constrained Passport lane for 32-bit devices whose OS kills the
/// default Rayon execution before it can emit a sample.
///
/// The pool is initialized during the warmup invocation and then reused by
/// all five measured samples. The distinct benchmark name keeps this
/// constrained execution policy visible in exported evidence.
#[benchmark]
pub fn bench_passport_complete_age_check_e2e_single_thread() {
    passport_single_thread_pool().install(run_passport_complete_age_check_e2e);
}

#[benchmark]
pub fn bench_passport_fragmented_age_check_prepare() {
    let prepared = profile_phase("prepare", || {
        passport::prepare_fragmented_age_check_fixture()
            .expect("prepare fragmented age_check fixture")
    });

    black_box((
        prepared.add_dsc.prover_size(),
        prepared.add_id_data.prover_size(),
        prepared.add_integrity_commit.prover_size(),
        prepared.attest.prover_size(),
    ));
}

#[benchmark(setup = setup_fragmented_age_check_provers, per_iteration)]
pub fn bench_passport_fragmented_age_check_prove(prepared: PreparedFragmentedAgeCheckProvers) {
    let proofs = profile_phase("prove", || {
        prove_fragmented_age_check_fixture_proof_only(prepared)
            .expect("prove fragmented age_check fixture")
    });

    black_box(proofs);
}

#[benchmark]
pub fn bench_oprf_prepare() {
    let prepared = profile_phase("prepare", || {
        examples::prepare_fixture(MobileBenchFixture::Oprf).expect("prepare oprf fixture")
    });

    black_box((
        prepared.prover_size(),
        prepared.constraint_count(),
        prepared.input_count(),
    ));
}

#[benchmark(setup = setup_oprf_prover, per_iteration)]
pub fn bench_oprf_prove(prepared: PreparedProverFixture) {
    let prove_started = Instant::now();
    let proof = profile_phase("prove", || {
        examples::prove_fixture_proof_only(prepared).expect("prove oprf fixture")
    });

    record_proof_metrics(&proof, prove_started);
    black_box(proof);
}

#[benchmark(setup = setup_oprf_verified)]
pub fn bench_oprf_verify(verified: &VerifiedCircuitFixture) {
    let verified = profile_phase("verify", || {
        examples::verify_fixture(verified.clone()).expect("verify oprf fixture")
    });

    black_box(verified);
}

#[benchmark]
pub fn bench_oprf_e2e() {
    static VALIDATION_GATE: Once = Once::new();
    VALIDATION_GATE.call_once(|| {
        let prepared = examples::prepare_fixture(MobileBenchFixture::Oprf)
            .expect("prepare oprf validation canary");
        let verified = examples::prove_fixture(prepared).expect("prove oprf validation canary");
        verified
            .verify_and_reject_tampered()
            .expect("validate oprf proof and tamper rejection");
    });

    let prepared = profile_phase("prepare", || {
        examples::prepare_fixture(MobileBenchFixture::Oprf).expect("prepare oprf fixture")
    });
    let verified = profile_phase("prove", || {
        examples::prove_fixture(prepared).expect("prove oprf fixture")
    });
    let verified = profile_phase("verify", || {
        examples::verify_fixture(verified).expect("verify oprf fixture")
    });

    black_box(verified);
}

#[benchmark]
pub fn bench_p256_bigcurve_prepare() {
    let prepared = profile_phase("prepare", || {
        examples::prepare_fixture(MobileBenchFixture::P256Bigcurve)
            .expect("prepare p256_bigcurve fixture")
    });

    black_box((
        prepared.prover_size(),
        prepared.constraint_count(),
        prepared.input_count(),
    ));
}

#[benchmark(setup = setup_p256_bigcurve_prover, per_iteration)]
pub fn bench_p256_bigcurve_prove(prepared: PreparedProverFixture) {
    let proof = profile_phase("prove", || {
        examples::prove_fixture_proof_only(prepared).expect("prove p256_bigcurve fixture")
    });

    black_box(proof);
}

#[benchmark(setup = setup_p256_bigcurve_verified)]
pub fn bench_p256_bigcurve_verify(verified: &VerifiedCircuitFixture) {
    let verified = profile_phase("verify", || {
        examples::verify_fixture(verified.clone()).expect("verify p256_bigcurve fixture")
    });

    black_box(verified);
}

#[benchmark]
pub fn bench_p256_bigcurve_e2e() {
    let prepared = profile_phase("prepare", || {
        examples::prepare_fixture(MobileBenchFixture::P256Bigcurve)
            .expect("prepare p256_bigcurve fixture")
    });
    let verified = profile_phase("prove", || {
        examples::prove_fixture(prepared).expect("prove p256_bigcurve fixture")
    });
    let verified = profile_phase("verify", || {
        examples::verify_fixture(verified).expect("verify p256_bigcurve fixture")
    });

    black_box(verified);
}

#[benchmark]
pub fn bench_webauthn_assertion_prepare() {
    let prepared = profile_phase("prepare", || {
        examples::prepare_fixture(MobileBenchFixture::WebauthnAssertion)
            .expect("prepare webauthn_assertion fixture")
    });

    black_box((
        prepared.prover_size(),
        prepared.constraint_count(),
        prepared.input_count(),
    ));
}

#[benchmark(setup = setup_webauthn_assertion_prover, per_iteration)]
pub fn bench_webauthn_assertion_prove(prepared: PreparedProverFixture) {
    let prove_started = Instant::now();
    let proof = profile_phase("prove", || {
        examples::prove_fixture_proof_only(prepared).expect("prove webauthn_assertion fixture")
    });

    record_proof_metrics(&proof, prove_started);
    black_box(proof);
}

#[benchmark(setup = setup_webauthn_assertion_verified)]
pub fn bench_webauthn_assertion_verify(verified: &VerifiedCircuitFixture) {
    let verified = profile_phase("verify", || {
        examples::verify_fixture(verified.clone()).expect("verify webauthn_assertion fixture")
    });

    black_box(verified);
}

#[benchmark]
pub fn bench_webauthn_assertion_e2e() {
    static VALIDATION_GATE: Once = Once::new();
    VALIDATION_GATE.call_once(|| {
        let prepared = examples::prepare_fixture(MobileBenchFixture::WebauthnAssertion)
            .expect("prepare webauthn_assertion validation canary");
        let verified =
            examples::prove_fixture(prepared).expect("prove webauthn_assertion validation canary");
        verified
            .verify_and_reject_tampered()
            .expect("validate webauthn_assertion proof and tamper rejection");
    });

    let prepared = profile_phase("prepare", || {
        examples::prepare_fixture(MobileBenchFixture::WebauthnAssertion)
            .expect("prepare webauthn_assertion fixture")
    });
    let verified = profile_phase("prove", || {
        examples::prove_fixture(prepared).expect("prove webauthn_assertion fixture")
    });
    let verified = profile_phase("verify", || {
        examples::verify_fixture(verified).expect("verify webauthn_assertion fixture")
    });

    black_box(verified);
}

#[cfg(test)]
mod tests {
    use super::{benchmark_start_metadata, BenchReport};

    #[test]
    fn lifecycle_metadata_records_observed_rayon_threads() {
        let metadata =
            benchmark_start_metadata("bench_mobile::bench_passport_complete_age_check_prove");

        assert_eq!(
            metadata["resolved_function"],
            "bench_mobile::bench_passport_complete_age_check_prove"
        );
        assert_eq!(metadata["rayon_threads"], rayon::current_num_threads());
        assert!(metadata["rayon_threads"]
            .as_u64()
            .is_some_and(|threads| threads > 0));
    }

    #[test]
    fn report_conversion_preserves_sample_resource_metrics() {
        let report = mobench_sdk::RunnerReport {
            spec:     mobench_sdk::BenchSpec {
                name:       "bench_mobile::bench_passport_complete_age_check_prove".to_string(),
                iterations: 1,
                warmup:     0,
            },
            samples:  vec![mobench_sdk::BenchSample {
                duration_ns:            123,
                cpu_time_ms:            Some(7),
                peak_memory_kb:         Some(48),
                process_peak_memory_kb: Some(1024),
            }],
            phases:   vec![],
            timeline: vec![],
        };

        let value =
            serde_json::to_value(BenchReport::from(report)).expect("serialize bench report");

        assert_eq!(value["samples"][0]["cpu_time_ms"], 7);
        assert_eq!(value["samples"][0]["peak_memory_kb"], 48);
        assert_eq!(value["samples"][0]["process_peak_memory_kb"], 1024);
    }

    #[test]
    fn report_conversion_preserves_timeline_spans() {
        let report = mobench_sdk::RunnerReport {
            spec:     mobench_sdk::BenchSpec {
                name:       "bench_mobile::bench_passport_complete_age_check_verify".to_string(),
                iterations: 1,
                warmup:     0,
            },
            samples:  vec![mobench_sdk::BenchSample {
                duration_ns:            321,
                cpu_time_ms:            None,
                peak_memory_kb:         None,
                process_peak_memory_kb: None,
            }],
            phases:   vec![],
            timeline: vec![mobench_sdk::HarnessTimelineSpan {
                phase:           "measured".to_string(),
                start_offset_ns: 10,
                end_offset_ns:   20,
                iteration:       Some(0),
            }],
        };

        let value =
            serde_json::to_value(BenchReport::from(report)).expect("serialize bench report");

        assert_eq!(value["timeline"][0]["phase"], "measured");
        assert_eq!(value["timeline"][0]["start_offset_ns"], 10);
        assert_eq!(value["timeline"][0]["end_offset_ns"], 20);
        assert_eq!(value["timeline"][0]["iteration"], 0);
    }
}
