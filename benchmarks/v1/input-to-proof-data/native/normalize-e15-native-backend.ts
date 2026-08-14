#!/usr/bin/env bun

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { validateAttempts } from "./export-benchmark-csv";
import type { AttemptRecord, Circuit, Prover } from "./schema";

interface MobenchSample {
  duration_ns: number;
  process_peak_memory_kb?: number | null;
  peak_memory_kb?: number | null;
}

interface MobenchReport {
  spec: {
    iterations: number;
    warmup: number;
    name: string;
  };
  samples: MobenchSample[];
  custom_metrics?: {
    run_u64?: Record<string, number>;
    sample_u64?: Record<string, number[]>;
  };
  resources?: {
    process_peak_memory_kb?: number | null;
    peak_memory_kb?: number | null;
  };
}

interface NativeLane {
  circuit: Circuit;
  circuit_variant: string;
  circuit_commit: string;
  prover: Extract<Prover, "noir_barretenberg" | "circom_groth16">;
  prover_backend: string;
  witness_backend: string;
  artifact_version: string;
  package_versions: Record<string, string | number | boolean>;
  artifact_hashes: Record<string, string>;
  evidence_path: string;
  report: MobenchReport;
}

interface E15NativeInput {
  campaign_id: string;
  recorded_at_utc: string;
  device: {
    model?: string;
    os?: string;
    abi?: string;
    zygote?: string;
  };
  lane: NativeLane;
}

interface E15NativeManifest {
  campaign_id: string;
  recorded_at_utc: string;
  source_commit: string;
  device: E15NativeInput["device"];
  lanes: Array<Omit<NativeLane, "report"> & { logcat_path: string }>;
}

export function extractMobenchReport(logcat: string): MobenchReport {
  const chunks: string[] = [];
  let collecting = false;
  let complete = false;
  for (const line of logcat.split(/\r?\n/)) {
    if (line.includes("BENCH_JSON_START")) {
      collecting = true;
      complete = false;
      chunks.length = 0;
      continue;
    }
    if (line.includes("BENCH_JSON_END") && collecting) {
      complete = true;
      break;
    }
    if (!collecting) continue;
    const marker = "BENCH_JSON_CHUNK ";
    const markerIndex = line.indexOf(marker);
    if (markerIndex >= 0) chunks.push(line.slice(markerIndex + marker.length));
  }
  if (!complete || chunks.length === 0) {
    throw new Error("retained logcat does not contain a complete BENCH_JSON report");
  }
  const report = JSON.parse(chunks.join("")) as MobenchReport;
  if (!report.spec || !Array.isArray(report.samples)) {
    throw new Error("BENCH_JSON report is missing its spec or samples");
  }
  return report;
}

export function normalizeE15NativeBackend(
  input: E15NativeInput,
  sourceCommit: string,
): AttemptRecord[] {
  if (input.device.abi !== "armeabi-v7a" || input.device.zygote !== "zygote32") {
    throw new Error(
      `E15 native result is not the canonical 32-bit target: ` +
        `${input.device.abi}/${input.device.zygote}`,
    );
  }

  const { lane } = input;
  const { report } = lane;
  if (
    report.spec.warmup !== 1 ||
    report.spec.iterations !== 5 ||
    report.samples.length !== 5
  ) {
    throw new Error(
      `${report.spec.name} violates the one-warmup/five-sequential-sample contract`,
    );
  }

  const proveTimes = report.custom_metrics?.sample_u64?.prove_time_ns;
  const proofSizes = report.custom_metrics?.sample_u64?.proof_size_bytes;
  const provingPayloadSize =
    report.custom_metrics?.run_u64?.proving_payload_size_bytes;
  if (
    !proveTimes ||
    proveTimes.length !== 6 ||
    !proofSizes ||
    proofSizes.length !== 6 ||
    !Number.isInteger(provingPayloadSize) ||
    provingPayloadSize! <= 0
  ) {
    throw new Error(
      `${report.spec.name} is missing exact prove time, proof size, or proving payload metrics`,
    );
  }

  const circuitSize =
    report.custom_metrics?.run_u64?.circuit_size_bytes ??
    report.custom_metrics?.run_u64?.zkey_size_bytes ??
    null;
  const attemptPrefix =
    `motorola-e15-${lane.prover}-${lane.circuit_variant}`.replaceAll(
      /[^a-zA-Z0-9._-]/g,
      "-",
    );
  const common = {
    campaign_id: input.campaign_id,
    recorded_at_utc: input.recorded_at_utc,
    hardware: "motorola_e15" as const,
    device_model: input.device.model ?? "moto e15",
    os_version: `Android ${input.device.os ?? "14"}`,
    abi: input.device.abi,
    runtime: "android_native" as const,
    browser: "",
    circuit: lane.circuit,
    circuit_variant: lane.circuit_variant,
    circuit_commit: lane.circuit_commit || sourceCommit,
    prover: lane.prover,
    frontend: lane.prover === "circom_groth16" ? "circom" : "noir",
    prover_backend: lane.prover_backend,
    witness_backend: lane.witness_backend,
    initialization_time_ms: null,
    witness_time_ms: null,
    verify_time_ms: null,
    circuit_size_bytes: circuitSize,
    artifact_size_bytes: provingPayloadSize!,
    bundle_size_bytes: provingPayloadSize!,
    constraint_count: null,
    artifact_version: lane.artifact_version,
    source_commit: sourceCommit,
    package_versions: JSON.stringify(lane.package_versions),
    artifact_hashes: JSON.stringify(lane.artifact_hashes),
    session_id: "",
    non_equivalence_note:
      "Closest available counterpart only; proof statements and implementation details are not equivalent.",
    failure_code: "",
    failure_detail: "",
    evidence_path: resolve(lane.evidence_path),
  };

  const records: AttemptRecord[] = [
    {
      ...common,
      attempt_id: `${attemptPrefix}-warmup`,
      sample_kind: "warmup",
      sample_index: 0,
      status: "ok",
      prover_time_ms: null,
      total_time_ms: null,
      peak_memory_mib: null,
      proof_size_bytes: null,
    },
  ];

  report.samples.forEach((sample, index) => {
    const peakMemoryKb =
      sample.process_peak_memory_kb ??
      sample.peak_memory_kb ??
      report.resources?.process_peak_memory_kb ??
      report.resources?.peak_memory_kb ??
      null;
    if (peakMemoryKb === null || peakMemoryKb <= 0) {
      throw new Error(`${report.spec.name} sample ${index + 1} is missing peak process memory`);
    }
    records.push({
      ...common,
      attempt_id: `${attemptPrefix}-sample-${index + 1}`,
      sample_kind: "measured",
      sample_index: index + 1,
      status: "ok",
      prover_time_ms: proveTimes[index + 1]! / 1_000_000,
      total_time_ms: sample.duration_ns / 1_000_000,
      peak_memory_mib: peakMemoryKb / 1024,
      proof_size_bytes: proofSizes[index + 1]!,
    });
  });

  return validateAttempts(records, false);
}

function usage(): never {
  console.error(
    "usage: bun normalize-e15-native-backend.ts <manifest.json> <attempts.json>",
  );
  process.exit(2);
}

if (import.meta.main) {
  const [manifestPath, outputPath] = process.argv.slice(2);
  if (!manifestPath || !outputPath) usage();
  const manifest = (await Bun.file(manifestPath).json()) as E15NativeManifest;
  if (!/^[0-9a-f]{40}$/.test(manifest.source_commit)) {
    throw new Error("manifest source_commit must be an immutable 40-character Git SHA");
  }
  const records = manifest.lanes.flatMap(({ logcat_path, ...lane }) =>
    normalizeE15NativeBackend(
      {
        campaign_id: manifest.campaign_id,
        recorded_at_utc: manifest.recorded_at_utc,
        device: manifest.device,
        lane: {
          ...lane,
          evidence_path: lane.evidence_path || logcat_path,
          report: extractMobenchReport(readFileSync(logcat_path, "utf8")),
        },
      },
      manifest.source_commit,
    ),
  );
  const validated = validateAttempts(records, false);
  await Bun.write(outputPath, `${JSON.stringify(validated, null, 2)}\n`);
  console.log(`normalized ${validated.length} E15 native backend rows into ${outputPath}`);
}
