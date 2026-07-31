#!/usr/bin/env bun

import { statSync } from "node:fs";
import { resolve } from "node:path";
import { toCsv, validateAttempts } from "./export-benchmark-csv";
import type { AttemptRecord, Circuit } from "./schema";

const repoRoot = resolve(import.meta.dir, "../../..");
const rawRoot = resolve(
  process.argv[2] ??
    resolve(repoRoot, "target/v1-benchmarks/reproduction/mac-chrome-20260729/raw"),
);
const outputJson = resolve(
  process.argv[3] ??
    resolve(repoRoot, "target/v1-benchmarks/reproduction/mac-chrome-20260729/attempts.json"),
);
const outputCsv = resolve(
  process.argv[4] ??
    resolve(repoRoot, "target/v1-benchmarks/reproduction/mac-chrome-20260729/samples.csv"),
);
const campaignId = process.env.CAMPAIGN_ID ?? "provekit-v1-cross-device-20260729";
const gitRevision = Bun.spawnSync(["git", "rev-parse", "HEAD"], {
  cwd: repoRoot,
  stdout: "pipe",
  stderr: "pipe",
});
if (gitRevision.exitCode !== 0) {
  throw new Error(`failed to resolve campaign source commit: ${gitRevision.stderr.toString()}`);
}
const sourceCommit =
  process.env.CAMPAIGN_SOURCE_COMMIT ?? gitRevision.stdout.toString().trim();
const browserIdentity = (await Bun.file(resolve(rawRoot, "provekit-oprf.json")).json()) as {
  browser?: { name?: unknown; version?: unknown; headless?: unknown };
};
if (
  typeof browserIdentity.browser?.name !== "string" ||
  typeof browserIdentity.browser.version !== "string" ||
  browserIdentity.browser.headless !== true
) {
  throw new Error("provekit-oprf.json is missing the canonical headless browser identity");
}
const browser =
  `${browserIdentity.browser.name} ${browserIdentity.browser.version} headless`;

interface BarretenbergSample {
  duration_ns: number;
  sample_index: number;
  warmup: boolean;
}

interface BarretenbergReport {
  status?: "build_failed" | "runtime_failed";
  failure_class?: string;
  failure_message?: string;
  samples?: BarretenbergSample[];
  metadata?: {
    backend: string;
    workload: string;
    proof_size_bytes: number;
    tampered_proof_rejected: boolean;
  };
  process_memory?: ProcessMemory;
  proving_payload_transport?: {
    crs_size_bytes: number;
  };
}

interface ProcessMemory {
  metric: "peak_chrome_renderer_rss";
  peak_rss_kib: number | null;
}

interface CircomSample {
  sample_index: number;
  warmup: boolean;
  status: "ok";
  initialization_time_ns: number | null;
  witness_time_ns: number;
  prove_time_ns: number;
  verify_time_ns: number;
  end_to_end_time_ns: number;
  proof_size_bytes: number;
  tampered_proof_rejected: boolean;
}

interface CircomResult {
  circuit: string;
  variant: string;
  wasm: string;
  zkey: string;
  verification_key: string;
  input: string;
  circuit_commit: string;
  samples: CircomSample[];
}

interface CircomReport {
  status?: "timed_out" | "runtime_failed";
  failure_class?: string;
  failure_message?: string;
  backend?: string;
  workload: Circuit;
  results?: CircomResult[];
  process_memory?: ProcessMemory;
}

interface ProveKitSample {
  iteration: number;
  warmup: boolean;
  prepare_time_ms: number;
  witness_time_ms?: number;
  prove_time_ms: number;
  verify_time_ms: number;
  end_to_end_time_ms: number;
  proof_size_bytes: number;
  tampered_proof_rejected: boolean;
  js_heap_bytes?: number;
}

interface ProveKitReport {
  benchmark: string;
  backend: string;
  initialization_time_ms: number;
  artifacts: {
    prover_bytes: number;
    verifier_bytes: number;
  };
  bundle: {
    shared_runtime_bytes: number;
    incremental_circuit_bytes: number;
    cold_download_bytes: number;
  };
  circuit: {
    constraints: number;
    witnesses: number;
  };
  warmup: number;
  iterations: number;
  samples: ProveKitSample[];
  process_memory?: ProcessMemory;
}

const records: AttemptRecord[] = [];
const hashCache = new Map<string, string>();

function recordedAt(path: string): string {
  return statSync(path).mtime.toISOString();
}

async function sha256(path: string): Promise<string> {
  const cached = hashCache.get(path);
  if (cached) return cached;
  const process = Bun.spawn(["shasum", "-a", "256", path], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const output = await new Response(process.stdout).text();
  if ((await process.exited) !== 0) {
    throw new Error(`failed to hash ${path}: ${await new Response(process.stderr).text()}`);
  }
  const hash = output.trim().split(/\s+/)[0];
  hashCache.set(path, hash);
  return hash;
}

function base(
  circuit: Circuit,
  circuitVariant: string,
  circuitCommit: string,
): Omit<
  AttemptRecord,
  | "attempt_id"
  | "recorded_at_utc"
  | "sample_kind"
  | "sample_index"
  | "status"
  | "initialization_time_ms"
  | "witness_time_ms"
  | "prover_time_ms"
  | "verify_time_ms"
  | "total_time_ms"
  | "peak_memory_mib"
  | "proof_size_bytes"
  | "circuit_size_bytes"
  | "artifact_size_bytes"
  | "bundle_size_bytes"
  | "constraint_count"
  | "artifact_version"
  | "package_versions"
  | "artifact_hashes"
  | "session_id"
  | "non_equivalence_note"
  | "failure_code"
  | "failure_detail"
  | "evidence_path"
  | "prover"
  | "frontend"
  | "prover_backend"
  | "witness_backend"
> {
  return {
    campaign_id: campaignId,
    hardware: "macbook_m4",
    device_model: "MacBook Pro M4 Max",
    os_version: "macOS 26.5.2 (25F84)",
    abi: "arm64",
    runtime: "browser_wasm",
    browser,
    circuit,
    circuit_variant: circuitVariant,
    circuit_commit: circuitCommit,
    source_commit: sourceCommit,
  };
}

function nsToMs(value: number | null): number | null {
  return value === null ? null : value / 1_000_000;
}

async function normalizeProveKit(
  fileName: string,
  circuit: Circuit,
  circuitVariant: string,
  circuitCommit: string,
) {
  const evidencePath = resolve(rawRoot, fileName);
  if (!(await Bun.file(evidencePath).exists()) || Bun.file(evidencePath).size === 0) return;
  const report = (await Bun.file(evidencePath).json()) as ProveKitReport;
  if (
    report.warmup !== 1 ||
    report.iterations !== 5 ||
    report.samples.length !== 6 ||
    !report.samples.every((sample) => sample.tampered_proof_rejected) ||
    report.samples.filter((sample) => sample.warmup).length !== 1
  ) {
    throw new Error(`${fileName} does not satisfy the 1+5 correctness contract`);
  }
  if (report.process_memory?.peak_rss_kib == null) {
    throw new Error(`${fileName} is missing Chrome renderer peak RSS`);
  }

  const assetRoot = resolve(repoRoot, "benchmarks/v1/wasm/dist/assets", circuitVariant);
  const proverPath = resolve(assetRoot, `${circuitVariant}.pkp`);
  const inputsPath = resolve(assetRoot, "inputs.json");
  const proverFile = Bun.file(proverPath);
  const inputsFile = Bun.file(inputsPath);
  const provingPayloadSize = proverFile.size + inputsFile.size;
  const hashes = {
    prover_sha256: await sha256(proverPath),
    inputs_sha256: await sha256(inputsPath),
  };
  const timestamp = recordedAt(evidencePath);

  for (const sample of report.samples) {
    const canonicalIndex = sample.warmup ? 0 : sample.iteration + 1;
    records.push({
      ...base(circuit, circuitVariant, circuitCommit),
      attempt_id: `mac-chrome-provekit-${circuitVariant}-${sample.warmup ? "warmup" : `sample-${canonicalIndex}`}`,
      recorded_at_utc: timestamp,
      prover: "provekit_v1",
      frontend: "noir",
      prover_backend: "provekit-v1-whir-wasm-single-thread",
      witness_backend: "@noir-lang/noir_js",
      sample_kind: sample.warmup ? "warmup" : "measured",
      sample_index: canonicalIndex,
      status: "ok",
      initialization_time_ms: report.initialization_time_ms,
      witness_time_ms: sample.witness_time_ms ?? null,
      prover_time_ms: sample.prove_time_ms,
      verify_time_ms: sample.verify_time_ms,
      total_time_ms: sample.end_to_end_time_ms,
      peak_memory_mib:
        report.process_memory?.peak_rss_kib == null
          ? null
          : report.process_memory.peak_rss_kib / 1024,
      proof_size_bytes: sample.proof_size_bytes,
      circuit_size_bytes: report.artifacts.prover_bytes,
      artifact_size_bytes: provingPayloadSize,
      bundle_size_bytes: provingPayloadSize,
      constraint_count: report.circuit.constraints,
      artifact_version: "pkp-2.0-pkv-2.1-noir-v1.0.0-beta.20",
      package_versions: JSON.stringify({
        "@worldcoin/provekit": "0.1.0",
        "@noir-lang/noir_js": "1.0.0-beta.20",
      }),
      artifact_hashes: JSON.stringify(hashes),
      session_id: "",
      non_equivalence_note:
        "Closest available counterpart only; proof statements and implementation details are not equivalent.",
      failure_code: "",
      failure_detail: "",
      evidence_path: evidencePath,
    });
  }
}

async function normalizeBarretenberg(
  fileName: string,
  circuit: Circuit,
  circuitVariant: string,
  circuitCommit: string,
  artifactRelative: string,
) {
  const evidencePath = resolve(rawRoot, fileName);
  if (!(await Bun.file(evidencePath).exists())) return;
  const report = (await Bun.file(evidencePath).json()) as BarretenbergReport;
  const timestamp = recordedAt(evidencePath);
  if (report.status) {
    records.push({
      ...base(circuit, circuitVariant, circuitCommit),
      attempt_id: `mac-chrome-noir-${circuitVariant}-gap`,
      recorded_at_utc: timestamp,
      prover: "noir_barretenberg",
      frontend: "noir",
      prover_backend: "barretenberg-ultrahonk-wasm-single-thread",
      witness_backend: "@noir-lang/noir_js",
      sample_kind: "gap",
      sample_index: null,
      status: report.status,
      initialization_time_ms: null,
      witness_time_ms: null,
      prover_time_ms: null,
      verify_time_ms: null,
      total_time_ms: null,
      peak_memory_mib: null,
      proof_size_bytes: null,
      circuit_size_bytes: null,
      artifact_size_bytes: null,
      bundle_size_bytes: null,
      constraint_count: null,
      artifact_version: "noir-v1.0.0-beta.19-acir",
      package_versions: JSON.stringify({
        "@aztec/bb.js": "4.2.0-aztecnr-rc.2",
        "@noir-lang/noir_js": "1.0.0-beta.19",
      }),
      artifact_hashes: JSON.stringify({}),
      session_id: "",
      non_equivalence_note:
        "Closest available counterpart only; proof statements and implementation details are not equivalent.",
      failure_code: report.failure_class ?? "browser_runtime",
      failure_detail: report.failure_message ?? "Barretenberg browser execution failed.",
      evidence_path: evidencePath,
    });
    return;
  }
  if (!report.samples || !report.metadata) {
    throw new Error(`${fileName} is missing samples or metadata`);
  }
  if (
    report.samples.length !== 6 ||
    !report.metadata.tampered_proof_rejected ||
    !report.samples.some((sample) => sample.warmup)
  ) {
    throw new Error(`${fileName} does not satisfy the 1+5 correctness contract`);
  }
  const artifactPath = resolve(repoRoot, artifactRelative);
  const artifactHash = await sha256(artifactPath);
  const provingAssetRoot = resolve(
    repoRoot,
    "benchmarks/v1/barretenberg/web/dist/assets",
    circuitVariant,
  );
  const provingCircuitPath = resolve(provingAssetRoot, "circuit.json");
  const provingWitnessPath = resolve(provingAssetRoot, "witness.gz");
  const provingCircuit = Bun.file(provingCircuitPath);
  const provingWitness = Bun.file(provingWitnessPath);
  const crsSize = report.proving_payload_transport?.crs_size_bytes;
  if (
    report.process_memory?.peak_rss_kib == null ||
    !Number.isSafeInteger(crsSize) ||
    crsSize! <= 0
  ) {
    throw new Error(`${fileName} is missing renderer RSS or exact CRS payload size`);
  }
  const provingPayloadSize = provingCircuit.size + provingWitness.size + crsSize!;
  const provingHashes = {
    circuit_sha256: await sha256(provingCircuitPath),
    witness_sha256: await sha256(provingWitnessPath),
  };

  for (const sample of report.samples) {
    const canonicalIndex = sample.warmup ? 0 : sample.sample_index + 1;
    records.push({
      ...base(circuit, circuitVariant, circuitCommit),
      attempt_id: `mac-chrome-noir-${circuitVariant}-${sample.warmup ? "warmup" : `sample-${canonicalIndex}`}`,
      recorded_at_utc: timestamp,
      prover: "noir_barretenberg",
      frontend: "noir",
      prover_backend: "barretenberg-ultrahonk-wasm-single-thread",
      witness_backend: "",
      sample_kind: sample.warmup ? "warmup" : "measured",
      sample_index: canonicalIndex,
      status: "ok",
      initialization_time_ms: null,
      witness_time_ms: null,
      prover_time_ms: nsToMs(sample.duration_ns),
      verify_time_ms: null,
      total_time_ms: nsToMs(sample.duration_ns),
      peak_memory_mib: report.process_memory.peak_rss_kib / 1024,
      proof_size_bytes: report.metadata.proof_size_bytes,
      circuit_size_bytes: provingCircuit.size,
      artifact_size_bytes: provingPayloadSize,
      bundle_size_bytes: provingPayloadSize,
      constraint_count: null,
      artifact_version: "noir-v1.0.0-beta.19-acir",
      package_versions: JSON.stringify({
        "@aztec/bb.js": "4.2.0-aztecnr-rc.2",
        "@noir-lang/noir_js": "1.0.0-beta.19",
      }),
      artifact_hashes: JSON.stringify({
        ...provingHashes,
        source_artifact_sha256: artifactHash,
      }),
      session_id: "",
      non_equivalence_note:
        "Closest available counterpart only; proof statements and implementation details are not equivalent.",
      failure_code: "",
      failure_detail: "",
      evidence_path: evidencePath,
    });
  }
}

async function normalizeCircom(fileName: string) {
  const evidencePath = resolve(rawRoot, fileName);
  if (!(await Bun.file(evidencePath).exists())) return;
  if (Bun.file(evidencePath).size === 0) return;
  const report = (await Bun.file(evidencePath).json()) as CircomReport;
  const timestamp = recordedAt(evidencePath);

  if (report.status) {
    const variant = report.workload === "webauthn" ? "webauthn_default" : `${report.workload}_all`;
    records.push({
      ...base(report.workload, variant, report.workload === "webauthn"
        ? "0fb5b4aa1398281c2fd3dbe14db147e05b61f201"
        : "unknown"),
      attempt_id: `mac-chrome-circom-${variant}-gap`,
      recorded_at_utc: timestamp,
      prover: "circom_groth16",
      frontend: "circom",
      prover_backend: "snarkjs-groth16-wasm",
      witness_backend: "snarkjs-wtns-calculate-wasm",
      sample_kind: "gap",
      sample_index: null,
      status: report.status,
      initialization_time_ms: null,
      witness_time_ms: null,
      prover_time_ms: null,
      verify_time_ms: null,
      total_time_ms: null,
      peak_memory_mib: null,
      proof_size_bytes: null,
      circuit_size_bytes: null,
      artifact_size_bytes: null,
      bundle_size_bytes: null,
      constraint_count: null,
      artifact_version: "circom-2.2.2-snarkjs-zkey",
      package_versions: JSON.stringify({ circom: "2.2.2", snarkjs: "0.7.6" }),
      artifact_hashes: JSON.stringify({}),
      session_id: "",
      non_equivalence_note:
        "Closest available counterpart only; proof statements and implementation details are not equivalent.",
      failure_code: report.failure_class ?? "browser_runtime",
      failure_detail: report.failure_message ?? "Circom browser execution failed.",
      evidence_path: evidencePath,
    });
    return;
  }
  if (report.process_memory?.peak_rss_kib == null) {
    throw new Error(`${fileName} is missing Chrome renderer peak RSS`);
  }

  for (const result of report.results ?? []) {
    if (
      result.samples.length !== 6 ||
      !result.samples.every(
        (sample) => sample.status === "ok" && sample.tampered_proof_rejected,
      )
    ) {
      throw new Error(`${fileName}/${result.variant} does not satisfy the 1+5 correctness contract`);
    }
    const fixtureRoot = resolve(repoRoot, "target/v1-benchmarks/circom-browser");
    const wasmPath = resolve(fixtureRoot, result.wasm);
    const zkeyPath = resolve(fixtureRoot, result.zkey);
    const inputPath = resolve(fixtureRoot, result.input);
    const files = [wasmPath, zkeyPath, inputPath].map((path) => Bun.file(path));
    const hashes = Object.fromEntries(
      await Promise.all(
        [
          ["wasm_sha256", wasmPath],
          ["zkey_sha256", zkeyPath],
          ["input_sha256", inputPath],
        ].map(async ([name, path]) => [name, await sha256(path)]),
      ),
    );

    for (const sample of result.samples) {
      const canonicalIndex = sample.warmup ? 0 : sample.sample_index + 1;
      records.push({
        ...base(report.workload, result.variant, result.circuit_commit),
        attempt_id: `mac-chrome-circom-${result.variant}-${sample.warmup ? "warmup" : `sample-${canonicalIndex}`}`,
        recorded_at_utc: timestamp,
        prover: "circom_groth16",
        frontend: "circom",
        prover_backend: report.backend ?? "snarkjs-groth16-wasm",
        witness_backend: "snarkjs-wtns-calculate-wasm",
        sample_kind: sample.warmup ? "warmup" : "measured",
        sample_index: canonicalIndex,
        status: "ok",
        initialization_time_ms: nsToMs(sample.initialization_time_ns),
        witness_time_ms: nsToMs(sample.witness_time_ns),
        prover_time_ms: nsToMs(sample.prove_time_ns),
        verify_time_ms: nsToMs(sample.verify_time_ns),
        total_time_ms: nsToMs(sample.end_to_end_time_ns),
        peak_memory_mib:
          report.process_memory?.peak_rss_kib == null
            ? null
            : report.process_memory.peak_rss_kib / 1024,
        proof_size_bytes: sample.proof_size_bytes,
        circuit_size_bytes: files[0].size,
        artifact_size_bytes: files[0].size + files[1].size + files[2].size,
        bundle_size_bytes: files[0].size + files[1].size + files[2].size,
        constraint_count:
          result.variant === "world_id_protocol_query"
            ? 20_966
            : result.variant === "world_id_protocol_nullifier"
              ? 53_677
              : result.variant === "privacy_ethereum_webauth_circom"
                ? 2_812_892
                : null,
        artifact_version: "circom-2.2.2-snarkjs-zkey",
        package_versions: JSON.stringify({ circom: "2.2.2", snarkjs: "0.7.6" }),
        artifact_hashes: JSON.stringify(hashes),
        session_id: "",
        non_equivalence_note:
          "Closest available counterpart only; proof statements and implementation details are not equivalent.",
        failure_code: "",
        failure_detail: "",
        evidence_path: evidencePath,
      });
    }
  }
}

await normalizeBarretenberg(
  "barretenberg-webauthn.json",
  "webauthn",
  "webauthn_assertion",
  "85aeeef539961cae5a63de794997b507a5975717",
  "target/v1-benchmarks/noir/webauthn_assertion/webauthn_assertion.json",
);
await normalizeBarretenberg(
  "barretenberg-oprf.json",
  "oprf",
  "oprf_taceo",
  "808f3c795b57963dd58ef282ccd61022ef39c285",
  "target/v1-benchmarks/noir/oprf_taceo/oprf_example.json",
);
await normalizeBarretenberg(
  "barretenberg-passport.json",
  "passport",
  "passport_complete_age_check",
  "13044531f0f38e02ed19fcbd9b26202b8ba5a962",
  "noir-examples/noir-passport-monolithic/complete_age_check/target/complete_age_check.json",
);
await normalizeProveKit(
  "provekit-passport.json",
  "passport",
  "passport_complete_age_check",
  "b0cd13cd7ca4aff71c1da609ddd32ae8113ac1ff",
);
await normalizeProveKit(
  "provekit-webauthn.json",
  "webauthn",
  "webauthn_assertion",
  "85aeeef539961cae5a63de794997b507a5975717",
);
await normalizeProveKit(
  "provekit-oprf.json",
  "oprf",
  "oprf_taceo",
  "fd37726215b59d3d4823ea7b1967b1da3525ed9d",
);
await normalizeCircom("circom-passport.json");
await normalizeCircom("circom-webauthn.json");
await normalizeCircom("circom-oprf.json");

const validated = validateAttempts(records, false);
await Bun.write(outputJson, `${JSON.stringify(validated, null, 2)}\n`);
await Bun.write(outputCsv, toCsv(validated));
console.log(`Normalized ${validated.length} Mac Chrome attempts`);
console.log(outputJson);
console.log(outputCsv);
