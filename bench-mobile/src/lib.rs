//! Mobile benchmarks for ProveKit's monolithic passport circuit.

use {
    crate::passport::{
        prove_complete_age_check_fixture, verify_complete_age_check_fixture,
        PreparedCompleteAgeCheckFixture, VerifiedCompleteAgeCheckFixture,
    },
    mobench_sdk::{benchmark, profile_phase},
    std::{cell::RefCell, hint::black_box},
};

pub mod passport;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct BenchSpec {
    pub name:       String,
    pub iterations: u32,
    pub warmup:     u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct BenchSample {
    pub duration_ns: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct SemanticPhase {
    pub name:        String,
    pub duration_ns: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct BenchResourceUsage {
    pub cpu_median_ms:  Option<u64>,
    pub peak_memory_kb: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct BenchReport {
    pub spec:           BenchSpec,
    pub samples:        Vec<BenchSample>,
    pub phases:         Vec<SemanticPhase>,
    pub resource_usage: Option<BenchResourceUsage>,
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
            duration_ns: sample.duration_ns,
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

impl From<mobench_sdk::BenchResourceUsage> for BenchResourceUsage {
    fn from(resource_usage: mobench_sdk::BenchResourceUsage) -> Self {
        Self {
            cpu_median_ms:  resource_usage.cpu_median_ms,
            peak_memory_kb: resource_usage.peak_memory_kb,
        }
    }
}

impl From<mobench_sdk::RunnerReport> for BenchReport {
    fn from(report: mobench_sdk::RunnerReport) -> Self {
        Self {
            spec:           report.spec.into(),
            samples:        report.samples.into_iter().map(Into::into).collect(),
            phases:         report.phases.into_iter().map(Into::into).collect(),
            resource_usage: report.resource_usage.map(Into::into),
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

#[uniffi::export]
pub fn run_benchmark(spec: BenchSpec) -> Result<BenchReport, BenchError> {
    let sdk_spec: mobench_sdk::BenchSpec = spec.into();
    let report = mobench_sdk::run_benchmark(sdk_spec)?;
    Ok(report.into())
}

uniffi::setup_scaffolding!();

thread_local! {
    static PREPARED_COMPLETE_AGE_CHECK: RefCell<Option<PreparedCompleteAgeCheckFixture>> =
        const { RefCell::new(None) };
    static VERIFIED_COMPLETE_AGE_CHECK: RefCell<Option<VerifiedCompleteAgeCheckFixture>> =
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

#[benchmark]
pub fn bench_passport_complete_age_check_prepare() {
    let prepared = profile_phase("prepare", || {
        passport::prepare_complete_age_check_fixture().expect("prepare complete_age_check fixture")
    });

    black_box((
        prepared.prover.size(),
        prepared.verifier.r1cs.num_constraints(),
        prepared.input_map.len(),
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
