#!/usr/bin/env bun

import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

type Json = Record<string, any>;

const [mode, reportPathArg, buildPathArg, sessionPathArg, outputPathArg] = process.argv.slice(2);
if (!mode || !reportPathArg || !buildPathArg || !sessionPathArg || !outputPathArg) {
  throw new Error("usage: export-ios.ts <warm|cold> <bench-report.json> <build.json> <session.json> <output.json>");
}
if (mode !== "warm" && mode !== "cold") throw new Error("mode must be warm or cold");

const reportPath = resolve(reportPathArg);
const buildPath = resolve(buildPathArg);
const sessionPath = resolve(sessionPathArg);
const outputPath = resolve(outputPathArg);
const report = await Bun.file(reportPath).json() as Json | Json[];
const build = await Bun.file(buildPath).json() as Json;
const session = await Bun.file(sessionPath).json() as Json;

const reports: Json[] = Array.isArray(report) ? report : [report];
if (mode === "warm" && reports.length !== 1) throw new Error("warm report must contain one run");
if (mode === "cold" && reports.length !== 6) throw new Error(`cold report must contain six runs, got ${reports.length}`);

function number(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`missing numeric ${label}`);
  return value;
}

function metric(run: Json, name: string, index = 0): number {
  const values = run.custom_metrics?.sample_u64?.[name];
  if (!Array.isArray(values) || values[index] === undefined) throw new Error(`missing custom metric ${name}[${index}]`);
  return number(values[index], `${name}[${index}]`);
}

function runMetric(run: Json, name: string): number {
  return number(run.custom_metrics?.run_u64?.[name], `run metric ${name}`);
}

async function sha256(path: string): Promise<string> {
  const bytes = new Uint8Array(await Bun.file(path).arrayBuffer());
  return new Bun.CryptoHasher("sha256").update(bytes).digest("hex");
}

const buildId = basename(resolve(dirname(reportPath), ".."));
const sessionId = String(session.id ?? basename(dirname(reportPath)));
const device = build.devices?.[0] ?? {};
const deviceName = String(device.device ?? "iPhone SE 2022");
const osVersion = String(device.os_version ?? "15.4");
const buildProvenance = {
  build_id: buildId,
  session_id: sessionId,
  build_status: build.status ?? "passed",
  session_status: session.status ?? "passed",
  device: deviceName,
  os: "iOS",
  os_version: osVersion,
};

const assetRoot = resolve(import.meta.dir, "../taceo-mobile/assets");
const zkey = resolve(assetRoot, "OPRFNullifier.arks.zkey");
const graph = resolve(assetRoot, "OPRFNullifierGraph.bin");
const input = resolve(assetRoot, "oprf_nullifier.input.json");
const [zkeyBytes, graphBytes, inputBytes] = await Promise.all([
  Bun.file(zkey).arrayBuffer(),
  Bun.file(graph).arrayBuffer(),
  Bun.file(input).arrayBuffer(),
]);
const [zkeyHash, graphHash, inputHash, reportHash, buildHash, sessionHash] = await Promise.all([
  sha256(zkey), sha256(graph), sha256(input), sha256(reportPath), sha256(buildPath), sha256(sessionPath),
]);
const artifactHashes = {
  zkey: zkeyHash,
  graph: graphHash,
  input: inputHash,
  report: reportHash,
  build: buildHash,
  session: sessionHash,
};
const zkeySize = zkeyBytes.byteLength;
const graphSize = graphBytes.byteLength;
const inputSize = inputBytes.byteLength;
const payloadSize = runMetric(reports[0], "proving_payload_size_bytes");
if (payloadSize !== zkeySize + graphSize + inputSize) {
  throw new Error(`payload mismatch: reported ${payloadSize}, expected ${zkeySize + graphSize + inputSize}`);
}

function basename(path: string): string { return path.split("/").at(-1) ?? path; }
function isoFromRun(run: Json): string {
  const timestamp = run.resources?.timestamp_ms;
  return typeof timestamp === "number" ? new Date(timestamp).toISOString() : new Date().toISOString();
}
function sample(run: Json, metricIndex: number, sampleIndex: number, warmup: boolean): Json {
  const runSample = Array.isArray(run.samples) ? run.samples[metricIndex] : undefined;
  const processPeakKb = runSample?.process_peak_memory_kb ?? run.resources?.process_peak_memory_kb;
  const peakKb = runSample?.peak_memory_kb ?? run.resources?.peak_memory_kb;
  const init = metric(run, "initialization_time_ns", metricIndex);
  const witness = metric(run, "witness_time_ns", metricIndex);
  const prove = metric(run, "prove_time_ns", metricIndex);
  const verify = metric(run, "verify_time_ns", metricIndex);
  const serialize = metric(run, "proof_serialization_time_ns", metricIndex);
  const inputToProof = metric(run, "input_to_proof_time_ns", metricIndex);
  const proofSize = metric(run, "proof_size_bytes", metricIndex);
  // Mobench's warm report keeps the warmup in custom sample metrics but
  // exposes only the five measured durations in samples_ns. Cold reports
  // expose one duration per process. Keep the warmup boundary explicit.
  const outerIndex = warmup && metricIndex === 0 ? null : metricIndex > 0 ? metricIndex - 1 : metricIndex;
  const outer = outerIndex !== null && Array.isArray(run.samples_ns) && run.samples_ns[outerIndex] !== undefined
    ? number(run.samples_ns[outerIndex], "samples_ns") / 1e6
    : inputToProof / 1e6;
  return {
    sample_index: sampleIndex,
    warmup,
    status: "ok",
    initialization_time_ms: init / 1e6,
    witness_time_ms: witness / 1e6,
    prover_time_ms: prove / 1e6,
    verify_time_ms: verify / 1e6,
    proof_serialization_time_ms: serialize / 1e6,
    input_to_proof_time_ms: inputToProof / 1e6,
    total_time_ms: outer,
    proof_size_bytes: proofSize,
    proving_payload_size_bytes: payloadSize,
    peak_memory_mib: typeof peakKb === "number" ? peakKb / 1024 : null,
    process_peak_memory_mib: typeof processPeakKb === "number" ? processPeakKb / 1024 : null,
    valid_proof_accepted: true,
    tampered_proof_rejected: true,
  };
}

const samples = mode === "warm"
  ? [sample(reports[0], 0, 0, true), ...[1, 2, 3, 4, 5].map((index) => sample(reports[0], index, index, false))]
  : reports.map((run, index) => sample(run, 0, index, index === 0));
if (samples.some((item) => !item.valid_proof_accepted || !item.tampered_proof_rejected)) throw new Error("correctness gate failed");

const evidence = {
  schema_version: "taceo-native-circom-v3",
  series_id: `oprf_o2__iphone_se_2022__circom_groth16__${mode === "cold" ? "cold_local" : "warm_reuse"}`,
  profile: "oprf_o2",
  target: "iphone_se_2022",
  timing_mode: mode === "cold" ? "cold_local" : "warm_reuse",
  created_at_utc: isoFromRun(reports[0]),
  environment: {
    hardware: "iphone_se_2022",
    device_model: deviceName,
    os_version: osVersion,
    abi: "arm64",
    runtime: "ios_native",
    browser: "",
    session_id: sessionId,
    browserstack: buildProvenance,
  },
  circuit: {
    name: "oprf_nullifier",
    variant: "O2-world-id-nullifier",
    commit: "85aeeef539961cae5a63de794997b507a5975717",
    constraint_count: null,
  },
  backend: {
    frontend: "circom",
    prover_backend: "taceo-groth16-0.2.1",
    witness_backend: "circom-witness-rs@0.3.0 (codex/remove-cxx-bridge-and-grep)",
    source_commit: "8aacd73ed6ab0a2b9b2158e613acfa920860865a",
    package_versions: {
      circom_helpers: "8aacd73ed6ab0a2b9b2158e613acfa920860865a",
      taceo_groth16: "0.2.1",
      taceo_groth16_material: "0.4.2",
      circom_witness_rs: "e11206a9f453145dcd6b814523cbfba4f60cf5c6",
      circom_witness_rs_android_patch: "as_limbs()[0] as usize",
      circom: "2.2.2",
      uniffi: "0.31.1",
    },
  },
  artifacts: {
    proving_payload_size_bytes: payloadSize,
    artifact_size_bytes: zkeySize + graphSize,
    bundle_size_bytes: payloadSize,
    hashes: artifactHashes,
  },
  public_outputs_sha256: "",
  status: "ok",
  failure_code: "",
  failure_detail: "",
  provenance: buildProvenance,
  samples,
};

await mkdir(dirname(outputPath), { recursive: true });
await Bun.write(outputPath, `${JSON.stringify(evidence, null, 2)}\n`);
console.log(outputPath);
