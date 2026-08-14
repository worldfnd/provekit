#!/usr/bin/env bun
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "../../../..");
const target = (process.env.TACEO_TARGET ?? "host") as "host" | "motorola_e15";
const mode = (process.env.TACEO_MODE ?? "warm") as "cold" | "warm";
const circuit = (process.env.TACEO_CIRCUIT ?? "oprf_nullifier") as "oprf_query" | "oprf_nullifier";
if (circuit !== "oprf_query" && circuit !== "oprf_nullifier") throw new Error("TACEO_CIRCUIT must be oprf_query or oprf_nullifier");
const samples = Number(process.env.TACEO_SAMPLES ?? "5");
const adb = process.env.ADB ?? resolve(process.env.ANDROID_HOME ?? `${process.env.HOME}/Library/Android/sdk`, "platform-tools/adb");
const serial = process.env.ANDROID_SERIAL ?? "ZY32M6782K";
const binary = target === "host"
  ? resolve(import.meta.dir, "target/release/taceo-oprf-benchmark")
  : "/data/local/tmp/taceo-v021/runner";
const assetStem = circuit === "oprf_query" ? "OPRFQuery" : "OPRFNullifier";
const inputStem = circuit === "oprf_query" ? "oprf_query" : "oprf_nullifier";
const zkey = target === "host"
  ? resolve(root, `benchmarks/v1/circom/taceo-mobile/assets/${assetStem}.arks.zkey`)
  : `/data/local/tmp/taceo-v021/${inputStem === "oprf_query" ? "query" : "nullifier"}.zkey`;
const graph = target === "host"
  ? resolve(root, `benchmarks/v1/circom/taceo-mobile/assets/${assetStem}Graph.bin`)
  : `/data/local/tmp/taceo-v021/${inputStem === "oprf_query" ? "query" : "nullifier"}.graph`;
const input = target === "host"
  ? resolve(root, `benchmarks/v1/circom/taceo-mobile/assets/${inputStem}.input.json`)
  : `/data/local/tmp/taceo-v021/${inputStem === "oprf_query" ? "query.input.json" : "input.json"}`;
const artifactRoot = resolve(root, "target/v1-benchmarks/taceo-v021/evidence");
const profileId = circuit === "oprf_nullifier" ? "oprf_o2" : "oprf_query";
const seriesId = `${profileId}__${target === "host" ? "mac_native_diagnostic" : "motorola_e15"}__circom_groth16__${mode === "cold" ? "cold_local" : "warm_reuse"}`;

async function command(args: string[]) {
  const child = Bun.spawn(args, { stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
  ]);
  if (exitCode !== 0) throw new Error(`${args.join(" ")} failed (${exitCode})\n${stderr}\n${stdout}`);
  return stdout.trim();
}

async function runProcess() {
  const args = [binary, zkey, graph, input, "warm", "0"];
  const report = target === "motorola_e15"
    ? JSON.parse(await command([adb, "-s", serial, "shell", ...args]))
    : JSON.parse(await command(args));
  return report.samples[0];
}

async function hash(path: string) {
  const bytes = new Uint8Array(await Bun.file(path).arrayBuffer());
  return { size_bytes: bytes.byteLength, sha256: new Bun.CryptoHasher("sha256").update(bytes).digest("hex") };
}

async function main() {
  if (!Number.isInteger(samples) || samples <= 0) throw new Error("TACEO_SAMPLES must be positive");
  if (mode !== "cold" && mode !== "warm") throw new Error("TACEO_MODE must be cold or warm");
  const raw = [] as Array<Record<string, unknown>>;
  if (mode === "cold") {
    for (let index = 0; index <= samples; index++) {
      console.error(`[${seriesId}] cold process ${index + 1}/${samples + 1}`);
      raw.push({ ...(await runProcess()), process_index: index });
    }
  } else {
    const args = [binary, zkey, graph, input, "warm", String(samples)];
    const report = target === "motorola_e15"
      ? JSON.parse(await command([adb, "-s", serial, "shell", ...args]))
      : JSON.parse(await command(args));
    raw.push(...report.samples);
  }
  const [zkeyMeta, graphMeta, inputMeta] = await Promise.all([
    hash(resolve(root, `benchmarks/v1/circom/taceo-mobile/assets/${assetStem}.arks.zkey`)),
    hash(resolve(root, `benchmarks/v1/circom/taceo-mobile/assets/${assetStem}Graph.bin`)),
    hash(resolve(root, `benchmarks/v1/circom/taceo-mobile/assets/${inputStem}.input.json`)),
  ]);
  const samplesOut = raw.map((sample, index) => ({
    sample_index: index,
    warmup: index === 0,
    status: "ok",
    initialization_time_ms: Number(sample.load_time_ms ?? 0),
    witness_time_ms: Number(sample.witness_time_ms),
    prover_time_ms: Number(sample.prove_time_ms),
    verify_time_ms: Number(sample.verify_time_ms),
    input_to_proof_time_ms: Number(sample.input_to_proof_time_ms),
    proof_size_bytes: Number(sample.proof_size_bytes),
    peak_memory_mib: Number(sample.peak_memory_mib),
    public_outputs_sha256: String(sample.public_outputs_sha256),
    valid_proof_accepted: Boolean(sample.valid_proof_accepted),
    tampered_proof_rejected: Boolean(sample.tampered_proof_rejected),
  }));
  if (samplesOut.some((sample) => !sample.valid_proof_accepted || !sample.tampered_proof_rejected)) {
    throw new Error("correctness gate failed");
  }
  const payload = zkeyMeta.size_bytes + graphMeta.size_bytes + inputMeta.size_bytes;
  const evidence = {
    schema_version: "taceo-native-circom-v2",
    series_id: seriesId,
    profile: "oprf_o2",
    target: target === "host" ? "mac_native_diagnostic" : "motorola_e15",
    timing_mode: mode === "cold" ? "cold_local" : "warm_reuse",
    created_at_utc: new Date().toISOString(),
    environment: target === "host"
      ? { hardware: "macbook_m4", device_model: "MacBook Pro (Apple M4 Max)", os_version: await command(["sw_vers", "-productVersion"]), abi: await command(["uname", "-m"]), runtime: "native_diagnostic", browser: "", session_id: "" }
      : { hardware: "motorola_e15", device_model: await command([adb, "-s", serial, "shell", "getprop", "ro.product.model"]), os_version: await command([adb, "-s", serial, "shell", "getprop", "ro.build.version.release"]), abi: await command([adb, "-s", serial, "shell", "getprop", "ro.product.cpu.abilist"]), runtime: "android_native", browser: "", session_id: serial },
    circuit: { name: circuit, variant: circuit === "oprf_query" ? "O2-world-id-query" : "O2-world-id-nullifier", commit: circuit === "oprf_query" ? "world-id-protocol-locked-artifacts" : "85aeeef539961cae5a63de794997b507a5975717", constraint_count: null },
    backend: {
      frontend: "circom",
      prover_backend: "taceo-groth16-0.2.1",
      witness_backend: "circom-witness-rs@0.3.0 (codex/remove-cxx-bridge-and-grep)",
      source_commit: "8aacd73ed6ab0a2b9b2158e613acfa920860865a",
      package_versions: { circom_helpers: "8aacd73ed6ab0a2b9b2158e613acfa920860865a", taceo_groth16: "0.2.1", taceo_groth16_material: "0.4.2", circom_witness_rs: "e11206a9f453145dcd6b814523cbfba4f60cf5c6", circom_witness_rs_android_patch: "as_limbs()[0] as usize", circom: "2.2.2" },
    },
    artifacts: { proving_payload_size_bytes: payload, artifact_size_bytes: zkeyMeta.size_bytes + graphMeta.size_bytes, bundle_size_bytes: payload, hashes: { zkey: zkeyMeta.sha256, graph: graphMeta.sha256, input: inputMeta.sha256 } },
    public_outputs_sha256: samplesOut[0]?.public_outputs_sha256 ?? "",
    status: "ok",
    failure_code: "",
    failure_detail: "",
    samples: samplesOut,
  };
  await mkdir(artifactRoot, { recursive: true });
  const output = resolve(artifactRoot, `${seriesId}.json`);
  await Bun.write(output, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(output);
}

await main();
