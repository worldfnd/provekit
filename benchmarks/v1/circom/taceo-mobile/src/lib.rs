use {
    ark_serialize::{CanonicalSerialize, Compress},
    mobench_sdk::benchmark,
    rand::{rngs::StdRng, SeedableRng},
    ruint::aliases::U256,
    serde::{Deserialize, Serialize},
    std::{
        collections::HashMap,
        hint::black_box,
        sync::{Once, OnceLock},
        time::Instant,
    },
    taceo_groth16_material::circom::{
        CircomGroth16Material, CircomGroth16MaterialBuilder, Validate,
    },
};

static NULLIFIER_ZKEY: &[u8] = include_bytes!("../assets/OPRFNullifier.arks.zkey");
static NULLIFIER_GRAPH: &[u8] = include_bytes!("../assets/OPRFNullifierGraph.bin");
static NULLIFIER_INPUT: &str = include_str!("../assets/oprf_nullifier.input.json");
static QUERY_ZKEY: &[u8] = include_bytes!("../assets/OPRFQuery.arks.zkey");
static QUERY_GRAPH: &[u8] = include_bytes!("../assets/OPRFQueryGraph.bin");
static QUERY_INPUT: &str = include_str!("../assets/oprf_query.input.json");
static NULLIFIER_MATERIAL: OnceLock<Result<CircomGroth16Material, String>> = OnceLock::new();
static QUERY_MATERIAL: OnceLock<Result<CircomGroth16Material, String>> = OnceLock::new();
static NULLIFIER_VALIDATED: Once = Once::new();
static QUERY_VALIDATED: Once = Once::new();
static NULLIFIER_RUN_METRICS: Once = Once::new();
static QUERY_RUN_METRICS: Once = Once::new();

#[derive(Debug, Clone, Copy)]
enum OprfCircuit {
    Query,
    Nullifier,
}

impl OprfCircuit {
    fn assets(self) -> (&'static [u8], &'static [u8], &'static str) {
        match self {
            Self::Query => (QUERY_ZKEY, QUERY_GRAPH, QUERY_INPUT),
            Self::Nullifier => (NULLIFIER_ZKEY, NULLIFIER_GRAPH, NULLIFIER_INPUT),
        }
    }
}

fn build_material(circuit: OprfCircuit) -> Result<CircomGroth16Material, String> {
    let (zkey, graph, _) = circuit.assets();
    CircomGroth16MaterialBuilder::new()
        .compress(Compress::No)
        .validate(Validate::Yes)
        .bbf_num_2_bits_helper()
        .bbf_inv()
        .bbf_legendre()
        .bbf_sqrt_input()
        .bbf_sqrt_unchecked()
        .build_from_bytes(zkey, graph)
        .map_err(|error| error.to_string())
}

fn material(circuit: OprfCircuit) -> Result<&'static CircomGroth16Material, String> {
    let material = match circuit {
        OprfCircuit::Query => &QUERY_MATERIAL,
        OprfCircuit::Nullifier => &NULLIFIER_MATERIAL,
    };
    material
        .get_or_init(|| build_material(circuit))
        .as_ref()
        .map_err(Clone::clone)
}

fn input(circuit: OprfCircuit) -> Result<HashMap<String, Vec<U256>>, String> {
    fn flatten(value: &serde_json::Value, out: &mut Vec<U256>) -> Result<(), String> {
        if let Some(values) = value.as_array() {
            for value in values {
                flatten(value, out)?;
            }
        } else if let Some(value) = value.as_str() {
            out.push(U256::from_str_radix(value, 10).map_err(|error| error.to_string())?);
        } else {
            return Err("OPRF input leaves must be decimal strings".to_owned());
        }
        Ok(())
    }
    let (_, _, input) = circuit.assets();
    let values: HashMap<String, serde_json::Value> =
        serde_json::from_str(input).map_err(|error| error.to_string())?;
    values
        .into_iter()
        .map(|(name, value)| {
            let mut flat = Vec::new();
            flatten(&value, &mut flat).map(|()| (name, flat))
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct BenchSpec {
    pub name:       String,
    pub iterations: u32,
    pub warmup:     u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct BenchSample {
    pub duration_ns:                 u64,
    /// Time spent initializing the proving material for this sample. This is
    /// non-zero only when the process initializes the material during the
    /// sample (the cold boundary); warm samples report zero.
    pub initialization_time_ns:      u64,
    /// Witness generation duration, kept separate for diagnostics.
    pub witness_time_ns:             u64,
    /// Groth16 proving duration, excluding witness generation and checks.
    pub prove_time_ns:               u64,
    /// Serialization duration for the exact proof bytes.
    pub proof_serialization_time_ns: u64,
    /// Exact compressed proof length in bytes.
    pub proof_size_bytes:            u64,
    /// Exact input-to-proof payload represented by this embedded runner.
    pub proving_payload_size_bytes:  u64,
    /// Explicit input-to-proof duration (initialization + witness + prove +
    /// serialization). Verification and tamper rejection are correctness
    /// gates and are intentionally outside this value.
    pub input_to_proof_time_ns:      u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_time_ms:                 Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_memory_kb:              Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_peak_memory_kb:      Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct SemanticPhase {
    pub name:        String,
    pub duration_ns: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct BenchResourceUsage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_total_ms:           Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_median_ms:          Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_memory_kb:         Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_memory_growth_kb:  Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_peak_memory_kb: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct HarnessTimelineSpan {
    pub phase:           String,
    pub start_offset_ns: u64,
    pub end_offset_ns:   u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iteration:       Option<u32>,
}
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct BenchReport {
    pub spec:           BenchSpec,
    pub samples:        Vec<BenchSample>,
    #[serde(default)]
    pub phases:         Vec<SemanticPhase>,
    #[serde(default)]
    pub timeline:       Vec<HarnessTimelineSpan>,
    #[serde(default)]
    pub resource_usage: Option<BenchResourceUsage>,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum BenchError {
    #[error("unknown benchmark function: {name}")]
    UnknownFunction { name: String },
    #[error("benchmark execution failed: {reason}")]
    ExecutionFailed { reason: String },
}

uniffi::setup_scaffolding!();

fn rss_kb() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage initializes the supplied rusage structure.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    #[cfg(target_os = "ios")]
    let bytes = unsafe { usage.assume_init().ru_maxrss as u64 };
    #[cfg(not(target_os = "ios"))]
    let bytes = unsafe { usage.assume_init().ru_maxrss as u64 } * 1024;
    Some(bytes / 1024)
}

fn payload_size(circuit: OprfCircuit) -> u64 {
    let (zkey, graph, input) = circuit.assets();
    (zkey.len() as u64)
        .saturating_add(graph.len() as u64)
        .saturating_add(input.len() as u64)
}

#[derive(Debug, Clone, Copy)]
struct Measurement {
    initialization_ns: u64,
    witness_ns:        u64,
    prove_ns:          u64,
    verify_ns:         u64,
    serialize_ns:      u64,
    proof_size:        u64,
    input_to_proof_ns: u64,
}

fn measurement(
    material: &CircomGroth16Material,
    inputs: &HashMap<String, Vec<U256>>,
    index: u32,
    initialization_ns: u64,
) -> Result<Measurement, String> {
    let witness_at = Instant::now();
    let witness = material
        .generate_witness(inputs)
        .map_err(|error| error.to_string())?;
    let witness_ns = witness_at.elapsed().as_nanos() as u64;

    let prove_at = Instant::now();
    let mut rng = StdRng::seed_from_u64(0x5441_4345_4f + index as u64);
    let (proof, public) = material
        .generate_proof_from_witness(&witness, &mut rng)
        .map_err(|error| error.to_string())?;
    let prove_ns = prove_at.elapsed().as_nanos() as u64;

    let serialize_at = Instant::now();
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|error| error.to_string())?;
    let serialize_ns = serialize_at.elapsed().as_nanos() as u64;

    // Correctness gates run after the timed input-to-proof interval. The
    // benchmark is rejected if either a valid proof fails or a tampered proof
    // verifies, while the published custom metric remains witness + prove +
    // serialization (plus material loading for cold samples).
    let verify_at = Instant::now();
    material
        .verify_proof(&proof, &public)
        .map_err(|error| error.to_string())?;
    let verify_ns = verify_at.elapsed().as_nanos() as u64;
    let mut tampered = proof.clone();
    tampered.a = Default::default();
    if material.verify_proof(&tampered, &public).is_ok() {
        return Err("tampered proof accepted".to_owned());
    }

    Ok(Measurement {
        initialization_ns,
        witness_ns,
        prove_ns,
        verify_ns,
        serialize_ns,
        proof_size: proof_bytes.len() as u64,
        input_to_proof_ns: initialization_ns
            .saturating_add(witness_ns)
            .saturating_add(prove_ns)
            .saturating_add(serialize_ns),
    })
}

fn record_static_metrics(circuit: OprfCircuit) {
    let (zkey, graph, input) = circuit.assets();
    let metrics = match circuit {
        OprfCircuit::Query => &QUERY_RUN_METRICS,
        OprfCircuit::Nullifier => &NULLIFIER_RUN_METRICS,
    };
    metrics.call_once(|| {
        mobench_sdk::record_run_u64("zkey_size_bytes", zkey.len() as u64);
        mobench_sdk::record_run_u64("graph_size_bytes", graph.len() as u64);
        mobench_sdk::record_run_u64("input_size_bytes", input.len() as u64);
        mobench_sdk::record_run_u64("proving_payload_size_bytes", payload_size(circuit));
    });
}

fn record_sample(measurement: Measurement) {
    mobench_sdk::record_sample_u64("initialization_time_ns", measurement.initialization_ns);
    mobench_sdk::record_sample_u64("witness_time_ns", measurement.witness_ns);
    mobench_sdk::record_sample_u64("prove_time_ns", measurement.prove_ns);
    mobench_sdk::record_sample_u64("verify_time_ns", measurement.verify_ns);
    mobench_sdk::record_sample_u64("proof_serialization_time_ns", measurement.serialize_ns);
    mobench_sdk::record_sample_u64("proof_size_bytes", measurement.proof_size);
    mobench_sdk::record_sample_u64("input_to_proof_time_ns", measurement.input_to_proof_ns);
    black_box(measurement);
}

fn validation_gate(circuit: OprfCircuit) {
    let validated = match circuit {
        OprfCircuit::Query => &QUERY_VALIDATED,
        OprfCircuit::Nullifier => &NULLIFIER_VALIDATED,
    };
    validated.call_once(|| {
        let material = build_material(circuit).expect("build TACEO OPRF material canary");
        let inputs = input(circuit).expect("parse TACEO OPRF input canary");
        measurement(&material, &inputs, 0, 0).expect("TACEO OPRF proof/tamper canary");
    });
}

struct PreparedWarm {
    material: &'static CircomGroth16Material,
    inputs:   HashMap<String, Vec<U256>>,
}

fn setup_warm_for(circuit: OprfCircuit) -> PreparedWarm {
    validation_gate(circuit);
    let material = material(circuit).expect("load TACEO OPRF material");
    let inputs = input(circuit).expect("parse TACEO OPRF inputs");
    record_static_metrics(circuit);
    PreparedWarm { material, inputs }
}

fn bench_warm(prepared: &PreparedWarm) {
    let measurement = measurement(prepared.material, &prepared.inputs, 1, 0)
        .expect("TACEO warm OPRF input-to-proof");
    record_sample(measurement);
}

fn bench_cold(circuit: OprfCircuit) {
    // The canary is deliberately built and checked outside the cold timer.
    // Each measured invocation then constructs fresh material, preserving the
    // cold load boundary instead of silently reusing the global OnceLock.
    validation_gate(circuit);
    record_static_metrics(circuit);
    let started = Instant::now();
    let material = build_material(circuit).expect("build TACEO cold OPRF material");
    let initialization_ns = started.elapsed().as_nanos() as u64;
    let inputs = input(circuit).expect("parse TACEO cold OPRF inputs");
    let measurement = measurement(&material, &inputs, 1, initialization_ns)
        .expect("TACEO cold OPRF input-to-proof");
    record_sample(measurement);
}

fn prove_once(
    circuit: OprfCircuit,
    index: u32,
) -> Result<(u64, u64, u64, u64, u64, u64), String> {
    let initialization_at = Instant::now();
    let material = material(circuit)?;
    let initialization_ns = initialization_at.elapsed().as_nanos() as u64;
    let inputs = input(circuit)?;
    let witness_at = Instant::now();
    let witness = material
        .generate_witness(&inputs)
        .map_err(|error| error.to_string())?;
    let witness_ns = witness_at.elapsed().as_nanos() as u64;
    let prove_at = Instant::now();
    let mut rng = StdRng::seed_from_u64(0x5441_4345_4f + index as u64);
    let (proof, public) = material
        .generate_proof_from_witness(&witness, &mut rng)
        .map_err(|error| error.to_string())?;
    let prove_ns = prove_at.elapsed().as_nanos() as u64;
    let verify_at = Instant::now();
    material
        .verify_proof(&proof, &public)
        .map_err(|error| error.to_string())?;
    let verify_ns = verify_at.elapsed().as_nanos() as u64;
    let serialize_at = Instant::now();
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|error| error.to_string())?;
    let serialize_ns = serialize_at.elapsed().as_nanos() as u64;
    let mut tampered = proof.clone();
    tampered.a = Default::default();
    if material.verify_proof(&tampered, &public).is_ok() {
        return Err("tampered proof accepted".to_owned());
    }
    Ok((
        initialization_ns,
        witness_ns,
        prove_ns,
        verify_ns,
        serialize_ns,
        proof_bytes.len() as u64,
    ))
}

#[uniffi::export]
pub fn run_benchmark(spec: BenchSpec) -> Result<BenchReport, BenchError> {
    let circuit = if spec.name.contains("query") {
        OprfCircuit::Query
    } else if spec.name.contains("nullifier") || spec.name.contains("oprf_input_to_proof") {
        OprfCircuit::Nullifier
    } else {
        return Err(BenchError::UnknownFunction { name: spec.name });
    };
    record_static_metrics(circuit);
    let mut warmup = 0;
    while warmup < spec.warmup {
        prove_once(circuit, warmup).map_err(|reason| BenchError::ExecutionFailed { reason })?;
        warmup += 1;
    }
    let mut samples = Vec::with_capacity(spec.iterations as usize);
    let mut last_phases = Vec::new();
    for index in 0..spec.iterations {
        let (initialization_ns, witness_ns, prove_ns, verify_ns, serialize_ns, proof_size) =
            prove_once(circuit, index + spec.warmup)
                .map_err(|reason| BenchError::ExecutionFailed { reason })?;
        let input_to_proof_time_ns = initialization_ns
            .saturating_add(witness_ns)
            .saturating_add(prove_ns)
            .saturating_add(serialize_ns);
        let payload_size = payload_size(circuit);
        last_phases = vec![
            SemanticPhase {
                name:        "initialization".to_owned(),
                duration_ns: initialization_ns,
            },
            SemanticPhase {
                name:        "witness".to_owned(),
                duration_ns: witness_ns,
            },
            SemanticPhase {
                name:        "prove".to_owned(),
                duration_ns: prove_ns,
            },
            SemanticPhase {
                name:        "verify".to_owned(),
                duration_ns: verify_ns,
            },
            SemanticPhase {
                name:        "proof_serialization".to_owned(),
                duration_ns: serialize_ns,
            },
        ];
        samples.push(BenchSample {
            duration_ns: input_to_proof_time_ns,
            initialization_time_ns: initialization_ns,
            witness_time_ns: witness_ns,
            prove_time_ns: prove_ns,
            proof_serialization_time_ns: serialize_ns,
            proof_size_bytes: proof_size,
            proving_payload_size_bytes: payload_size,
            input_to_proof_time_ns,
            cpu_time_ms: None,
            peak_memory_kb: rss_kb(),
            process_peak_memory_kb: rss_kb(),
        });
    }
    Ok(BenchReport {
        spec,
        samples,
        phases: last_phases,
        timeline: Vec::new(),
        resource_usage: None,
    })
}

/// Warm input-to-proof benchmark. Material is validated and initialized by
/// setup, then five measured iterations reuse it as a real warm process would.
fn setup_warm_query() -> PreparedWarm {
    setup_warm_for(OprfCircuit::Query)
}

fn setup_warm_nullifier() -> PreparedWarm {
    setup_warm_for(OprfCircuit::Nullifier)
}

#[benchmark(setup = setup_warm_query)]
pub fn bench_taceo_oprf_query_input_to_proof(prepared: &PreparedWarm) {
    bench_warm(prepared);
}

#[benchmark(setup = setup_warm_nullifier)]
pub fn bench_taceo_oprf_input_to_proof(prepared: &PreparedWarm) {
    bench_warm(prepared);
}

/// Cold input-to-proof benchmark. Every invocation constructs fresh proving
/// material, so the custom input-to-proof metric includes the load boundary.
#[benchmark]
pub fn bench_taceo_oprf_query_input_to_proof_cold() {
    bench_cold(OprfCircuit::Query);
}

#[benchmark]
pub fn bench_taceo_oprf_input_to_proof_cold() {
    bench_cold(OprfCircuit::Nullifier);
}

mobench_sdk::export_native_c_abi!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_taceo_oprf_benchmarks() {
        let names = mobench_sdk::list_benchmark_names();
        assert!(
            names
                .iter()
                .any(|name| { name.ends_with("::bench_taceo_oprf_input_to_proof") }),
            "registered benchmarks: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|name| { name.ends_with("::bench_taceo_oprf_input_to_proof_cold") }),
            "registered benchmarks: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|name| { name.ends_with("::bench_taceo_oprf_query_input_to_proof") }),
            "registered benchmarks: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|name| { name.ends_with("::bench_taceo_oprf_query_input_to_proof_cold") }),
            "registered benchmarks: {names:?}"
        );
    }

    #[test]
    fn frozen_fixture_proves_verifies_and_rejects_tampering() {
        validation_gate(OprfCircuit::Query);
        validation_gate(OprfCircuit::Nullifier);
    }
}
