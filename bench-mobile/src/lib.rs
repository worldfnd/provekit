//! Mobile benchmarks for ProveKit passport and example circuits.

use {
    crate::passport::{
        prove_complete_age_check_fixture, prove_complete_age_check_fixture_proof_only,
        prove_fragmented_age_check_fixture_proof_only, verify_complete_age_check_fixture,
        PreparedCompleteAgeCheckFixture, PreparedFragmentedAgeCheckFixture,
        VerifiedCompleteAgeCheckFixture,
    },
    examples::{MobileBenchFixture, PreparedCircuitFixture, VerifiedCircuitFixture},
    mobench_sdk::{benchmark, profile_phase},
    serde_json::json,
    std::hint::black_box,
};

pub mod examples;
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

#[cfg(target_os = "android")]
fn configure_android_complete_age_check_threads(function: &str) {
    use std::sync::Once;

    static INIT: Once = Once::new();

    if function != "bench_mobile::bench_passport_complete_age_check_prove" {
        return;
    }

    INIT.call_once(|| {
        let threads = std::env::var("PROVEKIT_ANDROID_COMPLETE_AGE_RAYON_THREADS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|threads| *threads > 0)
            .unwrap_or(1);

        match rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
        {
            Ok(()) => log_benchmark_lifecycle(
                "rayon_configured",
                function,
                0,
                0,
                json!({ "threads": threads }),
            ),
            Err(error) => log_benchmark_lifecycle(
                "rayon_config_skipped",
                function,
                0,
                0,
                json!({ "threads": threads, "error": error.to_string() }),
            ),
        }
    });
}

#[cfg(not(target_os = "android"))]
fn configure_android_complete_age_check_threads(_function: &str) {}

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

pub fn run_benchmark(spec: BenchSpec) -> Result<BenchReport, BenchError> {
    let function = spec.name.clone();
    let iterations = spec.iterations;
    let warmup = spec.warmup;
    configure_android_complete_age_check_threads(&function);
    log_benchmark_lifecycle(
        "start",
        &function,
        iterations,
        warmup,
        json!({
            "resolved_function": function,
        }),
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
    passport::prepare_complete_age_check_fixture().expect("prepare complete_age_check fixture")
}

fn setup_complete_age_check_verified() -> VerifiedCompleteAgeCheckFixture {
    let prepared = setup_complete_age_check_prepared();
    prove_complete_age_check_fixture(prepared).expect("prove complete_age_check fixture")
}

fn setup_fragmented_age_check_prepared() -> PreparedFragmentedAgeCheckFixture {
    passport::prepare_fragmented_age_check_fixture().expect("prepare fragmented age_check fixture")
}

fn setup_oprf_prepared() -> PreparedCircuitFixture {
    examples::prepare_fixture(MobileBenchFixture::Oprf).expect("prepare oprf fixture")
}

fn setup_oprf_verified() -> VerifiedCircuitFixture {
    let prepared = setup_oprf_prepared();
    examples::prove_fixture(prepared).expect("prove oprf fixture")
}

fn setup_p256_bigcurve_prepared() -> PreparedCircuitFixture {
    examples::prepare_fixture(MobileBenchFixture::P256Bigcurve)
        .expect("prepare p256_bigcurve fixture")
}

fn setup_p256_bigcurve_verified() -> VerifiedCircuitFixture {
    let prepared = setup_p256_bigcurve_prepared();
    examples::prove_fixture(prepared).expect("prove p256_bigcurve fixture")
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

#[benchmark(setup = setup_complete_age_check_prepared, per_iteration)]
pub fn bench_passport_complete_age_check_prove(prepared: PreparedCompleteAgeCheckFixture) {
    let proof = profile_phase("prove", || {
        prove_complete_age_check_fixture_proof_only(prepared)
            .expect("prove complete_age_check fixture")
    });

    black_box(proof);
}

#[benchmark(setup = setup_complete_age_check_verified)]
pub fn bench_passport_complete_age_check_verify(verified: &VerifiedCompleteAgeCheckFixture) {
    let verified = profile_phase("verify", || {
        verify_complete_age_check_fixture(verified.clone())
            .expect("verify complete_age_check fixture")
    });

    black_box(verified);
}

#[benchmark]
pub fn bench_passport_complete_age_check_e2e() {
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

#[benchmark(setup = setup_fragmented_age_check_prepared, per_iteration)]
pub fn bench_passport_fragmented_age_check_prove(prepared: PreparedFragmentedAgeCheckFixture) {
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

#[benchmark(setup = setup_oprf_prepared, per_iteration)]
pub fn bench_oprf_prove(prepared: PreparedCircuitFixture) {
    let proof = profile_phase("prove", || {
        examples::prove_fixture_proof_only(prepared).expect("prove oprf fixture")
    });

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

#[benchmark(setup = setup_p256_bigcurve_prepared, per_iteration)]
pub fn bench_p256_bigcurve_prove(prepared: PreparedCircuitFixture) {
    let verified = profile_phase("prove", || {
        examples::prove_fixture(prepared).expect("prove p256_bigcurve fixture")
    });

    black_box(verified);
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

#[cfg(test)]
mod tests {
    use super::BenchReport;

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
