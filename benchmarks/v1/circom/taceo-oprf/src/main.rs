use ark_serialize::{CanonicalSerialize, Compress};
use rand::{rngs::StdRng, SeedableRng};
use ruint::aliases::U256;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, env, fs, io::Write, path::Path, time::Instant};
use taceo_groth16_material::circom::{CircomGroth16Material, CircomGroth16MaterialBuilder, Validate};

#[derive(serde::Serialize)]
struct Sample {
    sample_index: usize,
    warmup: bool,
    status: &'static str,
    load_time_ms: f64,
    witness_time_ms: f64,
    prove_time_ms: f64,
    proof_serialization_time_ms: f64,
    verify_time_ms: f64,
    input_to_proof_time_ms: f64,
    proof_size_bytes: usize,
    public_outputs_sha256: String,
    valid_proof_accepted: bool,
    tampered_proof_rejected: bool,
    peak_memory_mib: f64,
}

fn flatten(name: &str, value: Value, output: &mut Vec<U256>) -> Result<(), String> {
    match value {
        Value::Array(values) => {
            values.into_iter().try_for_each(|value| flatten(name, value, output))?;
        }
        Value::String(text) => {
            output.push(U256::from_str_radix(&text, 10).map_err(|e| format!("{name}: {e}"))?);
        }
        Value::Number(number) => {
            output.push(U256::from_str_radix(&number.to_string(), 10).map_err(|e| format!("{name}: {e}"))?);
        }
        other => return Err(format!("{name}: unsupported input {other}")),
    }
    Ok(())
}

fn read_input(path: &Path) -> Result<HashMap<String, Vec<U256>>, Box<dyn std::error::Error>> {
    let values: HashMap<String, Value> = serde_json::from_slice(&fs::read(path)?)?;
    values.into_iter().map(|(name, value)| {
        let mut flat = Vec::new();
        flatten(&name, value, &mut flat)?;
        Ok((name, flat))
    }).collect::<Result<_, String>>().map_err(Into::into)
}

fn rss_mib() -> f64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage initializes the supplied rusage structure.
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if result != 0 { return 0.0; }
    #[cfg(target_os = "macos")]
    let bytes = unsafe { usage.assume_init().ru_maxrss as f64 };
    #[cfg(not(target_os = "macos"))]
    let bytes = unsafe { usage.assume_init().ru_maxrss as f64 } * 1024.0;
    bytes / (1024.0 * 1024.0)
}

fn millis(start: Instant) -> f64 { start.elapsed().as_secs_f64() * 1000.0 }

fn sha256<T: CanonicalSerialize>(value: &T) -> Result<String, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes)?;
    Ok(Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect())
}

fn one(
    material: &CircomGroth16Material,
    input: &HashMap<String, Vec<U256>>,
    index: usize,
    warmup: bool,
    load_time_ms: f64,
) -> Result<Sample, Box<dyn std::error::Error>> {
    let witness_at = Instant::now();
    let witness = material.generate_witness(input)?;
    let witness_time_ms = millis(witness_at);
    let prove_at = Instant::now();
    let mut rng = StdRng::seed_from_u64(0x5441_4345_4f + index as u64);
    let (proof, public) = material.generate_proof_from_witness(&witness, &mut rng)?;
    let prove_time_ms = millis(prove_at);
    let verify_at = Instant::now();
    material.verify_proof(&proof, &public)?;
    let verify_time_ms = millis(verify_at);
    let serialize_at = Instant::now();
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)?;
    let proof_serialization_time_ms = millis(serialize_at);
    let public_outputs_sha256 = sha256(&public)?;
    let mut tampered = proof.clone();
    tampered.a = Default::default();
    let tampered_proof_rejected = material.verify_proof(&tampered, &public).is_err();
    if !tampered_proof_rejected { return Err("tampered proof accepted".into()); }
    Ok(Sample {
        sample_index: index,
        warmup,
        status: "ok",
        load_time_ms,
        witness_time_ms,
        prove_time_ms,
        verify_time_ms,
        input_to_proof_time_ms: load_time_ms + witness_time_ms + prove_time_ms + proof_serialization_time_ms,
        proof_serialization_time_ms,
        proof_size_bytes: proof_bytes.len(),
        public_outputs_sha256,
        valid_proof_accepted: true,
        tampered_proof_rejected,
        peak_memory_mib: rss_mib(),
    })
}

fn load(zkey: &Path, graph: &Path) -> Result<(CircomGroth16Material, f64), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let material = CircomGroth16MaterialBuilder::new()
        .compress(Compress::No)
        .validate(Validate::Yes)
        .bbf_num_2_bits_helper()
        .bbf_inv()
        .bbf_legendre()
        .bbf_sqrt_input()
        .bbf_sqrt_unchecked()
        .build_from_paths(zkey, graph)?;
    Ok((material, millis(start)))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 || args.len() > 6 {
        eprintln!("usage: taceo-oprf-benchmark <zkey> <graph> <input.json> <cold|warm> [samples]");
        std::process::exit(2);
    }
    let zkey = Path::new(&args[1]);
    let graph = Path::new(&args[2]);
    let input = read_input(Path::new(&args[3]))?;
    let mode = &args[4];
    let samples = match args.get(5) {
        Some(value) => value.parse::<usize>().map_err(|_| "samples must be an integer")?,
        None => 5,
    };
    let mut out = std::io::BufWriter::new(std::io::stdout());
    let mut samples_out = Vec::new();
    if mode == "cold" {
        for index in 0..=samples {
            let (material, load_time_ms) = load(zkey, graph)?;
            samples_out.push(one(&material, &input, index, index == 0, load_time_ms)?);
        }
    } else if mode == "warm" {
        let (material, load_time_ms) = load(zkey, graph)?;
        for index in 0..=samples {
            samples_out.push(one(&material, &input, index, index == 0, if index == 0 { load_time_ms } else { 0.0 })?);
        }
    } else {
        return Err("mode must be cold or warm".into());
    }
    serde_json::to_writer_pretty(&mut out, &serde_json::json!({
        "schema_version": 1,
        "mode": mode,
        "samples": samples_out,
        "prover_backend": "taceo-groth16-0.2.1",
        "witness_backend": "circom-witness-rs-codex-remove-cxx-bridge-and-grep-e11206a9",
    }))?;
    out.write_all(b"\n")?;
    Ok(())
}
