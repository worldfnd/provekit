//! Mobile benchmarks for ProveKit's monolithic passport circuit.

use {
    crate::passport::{
        prove_complete_age_check_fixture, verify_complete_age_check_fixture,
        PreparedCompleteAgeCheckFixture, VerifiedCompleteAgeCheckFixture,
    },
    examples::{MobileBenchFixture, PreparedCircuitFixture, VerifiedCircuitFixture},
    mobench_sdk::{benchmark, profile_phase},
    serde_json::json,
    std::{cell::RefCell, hint::black_box},
};

pub mod examples;
pub mod passport;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct BenchSpec {
    pub name:       String,
    pub iterations: u32,
    pub warmup:     u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct BenchSample {
    pub duration_ns:            u64,
    pub cpu_time_ms:            Option<u64>,
    pub peak_memory_kb:         Option<u64>,
    pub process_peak_memory_kb: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct SemanticPhase {
    pub name:        String,
    pub duration_ns: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct HarnessTimelineSpan {
    pub phase:           String,
    pub start_offset_ns: u64,
    pub end_offset_ns:   u64,
    pub iteration:       Option<u32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct BenchReport {
    pub spec:     BenchSpec,
    pub samples:  Vec<BenchSample>,
    pub phases:   Vec<SemanticPhase>,
    pub timeline: Vec<HarnessTimelineSpan>,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
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

#[uniffi::export]
pub fn run_benchmark(spec: BenchSpec) -> Result<BenchReport, BenchError> {
    let function = spec.name.clone();
    let iterations = spec.iterations;
    let warmup = spec.warmup;
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

uniffi::setup_scaffolding!();

thread_local! {
    static PREPARED_COMPLETE_AGE_CHECK: RefCell<Option<PreparedCompleteAgeCheckFixture>> =
        const { RefCell::new(None) };
    static VERIFIED_COMPLETE_AGE_CHECK: RefCell<Option<VerifiedCompleteAgeCheckFixture>> =
        const { RefCell::new(None) };
    static PREPARED_OPRF: RefCell<Option<PreparedCircuitFixture>> =
        const { RefCell::new(None) };
    static VERIFIED_OPRF: RefCell<Option<VerifiedCircuitFixture>> =
        const { RefCell::new(None) };
    static PREPARED_P256_BIGCURVE: RefCell<Option<PreparedCircuitFixture>> =
        const { RefCell::new(None) };
    static VERIFIED_P256_BIGCURVE: RefCell<Option<VerifiedCircuitFixture>> =
        const { RefCell::new(None) };
}

fn with_prepared_complete_age_check<T>(f: impl FnOnce(&PreparedCompleteAgeCheckFixture) -> T) -> T {
    PREPARED_COMPLETE_AGE_CHECK.with(|cache| {
        if cache.borrow().is_none() {
            *cache.borrow_mut() = Some(
                passport::prepare_complete_age_check_fixture()
                    .expect("prepare complete_age_check fixture"),
            );
        }

        let cache_ref = cache.borrow();
        let prepared = cache_ref
            .as_ref()
            .expect("prepared complete_age_check fixture");
        f(prepared)
    })
}

fn with_verified_complete_age_check<T>(f: impl FnOnce(&VerifiedCompleteAgeCheckFixture) -> T) -> T {
    VERIFIED_COMPLETE_AGE_CHECK.with(|cache| {
        if cache.borrow().is_none() {
            let prepared = passport::prepare_complete_age_check_fixture().expect("prepare fixture");
            let verified = prove_complete_age_check_fixture(prepared).expect("prove fixture");
            *cache.borrow_mut() = Some(verified);
        }

        let cache_ref = cache.borrow();
        let verified = cache_ref
            .as_ref()
            .expect("verified complete_age_check fixture");
        f(verified)
    })
}

fn with_prepared_oprf<T>(f: impl FnOnce(&PreparedCircuitFixture) -> T) -> T {
    PREPARED_OPRF.with(|cache| {
        if cache.borrow().is_none() {
            *cache.borrow_mut() = Some(
                examples::prepare_fixture(MobileBenchFixture::Oprf).expect("prepare oprf fixture"),
            );
        }

        let cache_ref = cache.borrow();
        let prepared = cache_ref.as_ref().expect("prepared oprf fixture");
        f(prepared)
    })
}

fn with_verified_oprf<T>(f: impl FnOnce(&VerifiedCircuitFixture) -> T) -> T {
    VERIFIED_OPRF.with(|cache| {
        if cache.borrow().is_none() {
            let prepared =
                examples::prepare_fixture(MobileBenchFixture::Oprf).expect("prepare oprf fixture");
            let verified = examples::prove_fixture(prepared).expect("prove oprf fixture");
            *cache.borrow_mut() = Some(verified);
        }

        let cache_ref = cache.borrow();
        let verified = cache_ref.as_ref().expect("verified oprf fixture");
        f(verified)
    })
}

fn with_prepared_p256_bigcurve<T>(f: impl FnOnce(&PreparedCircuitFixture) -> T) -> T {
    PREPARED_P256_BIGCURVE.with(|cache| {
        if cache.borrow().is_none() {
            *cache.borrow_mut() = Some(
                examples::prepare_fixture(MobileBenchFixture::P256Bigcurve)
                    .expect("prepare p256_bigcurve fixture"),
            );
        }

        let cache_ref = cache.borrow();
        let prepared = cache_ref.as_ref().expect("prepared p256_bigcurve fixture");
        f(prepared)
    })
}

fn with_verified_p256_bigcurve<T>(f: impl FnOnce(&VerifiedCircuitFixture) -> T) -> T {
    VERIFIED_P256_BIGCURVE.with(|cache| {
        if cache.borrow().is_none() {
            let prepared = examples::prepare_fixture(MobileBenchFixture::P256Bigcurve)
                .expect("prepare p256_bigcurve fixture");
            let verified = examples::prove_fixture(prepared).expect("prove p256_bigcurve fixture");
            *cache.borrow_mut() = Some(verified);
        }

        let cache_ref = cache.borrow();
        let verified = cache_ref.as_ref().expect("verified p256_bigcurve fixture");
        f(verified)
    })
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

#[benchmark]
pub fn bench_passport_complete_age_check_prove() {
    with_prepared_complete_age_check(|prepared| {
        let verified = profile_phase("prove", || {
            prove_complete_age_check_fixture(prepared.clone())
                .expect("prove complete_age_check fixture")
        });

        black_box(verified);
    });
}

#[benchmark]
pub fn bench_passport_complete_age_check_verify() {
    with_verified_complete_age_check(|verified| {
        let verified = profile_phase("verify", || {
            verify_complete_age_check_fixture(verified.clone())
                .expect("verify complete_age_check fixture")
        });

        black_box(verified);
    });
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

#[benchmark]
pub fn bench_oprf_prove() {
    with_prepared_oprf(|prepared| {
        let verified = profile_phase("prove", || {
            examples::prove_fixture(prepared.clone()).expect("prove oprf fixture")
        });

        black_box(verified);
    });
}

#[benchmark]
pub fn bench_oprf_verify() {
    with_verified_oprf(|verified| {
        let verified = profile_phase("verify", || {
            examples::verify_fixture(verified.clone()).expect("verify oprf fixture")
        });

        black_box(verified);
    });
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

#[benchmark]
pub fn bench_p256_bigcurve_prove() {
    with_prepared_p256_bigcurve(|prepared| {
        let verified = profile_phase("prove", || {
            examples::prove_fixture(prepared.clone()).expect("prove p256_bigcurve fixture")
        });

        black_box(verified);
    });
}

#[benchmark]
pub fn bench_p256_bigcurve_verify() {
    with_verified_p256_bigcurve(|verified| {
        let verified = profile_phase("verify", || {
            examples::verify_fixture(verified.clone()).expect("verify p256_bigcurve fixture")
        });

        black_box(verified);
    });
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
