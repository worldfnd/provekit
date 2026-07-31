#!/usr/bin/env bun

import { statSync } from "node:fs";
import { resolve } from "node:path";
import { validateAttempts } from "./export-benchmark-csv";
import type { AttemptRecord, Circuit, Status } from "./schema";

interface MobenchSample {
  duration_ns: number;
  process_peak_memory_kb?: number | null;
  peak_memory_kb?: number | null;
}
interface CustomMetrics {
  sample_u64?: Record<string, number[]>;
  run_u64?: Record<string, number>;
}
interface E15Apk {
  path: string;
  sha256: string;
  bytes: number;
}
interface E15Result {
  workload: Circuit;
  function: string;
  status: "ok" | "runtime_failed" | "crashed" | "timed_out" | "not_run";
  report?: {
    spec: { iterations: number; warmup: number };
    samples: MobenchSample[];
    custom_metrics?: CustomMetrics;
  };
  failure?: { kind?: string; message?: string } | null;
  evidence_path: string;
  apk?: E15Apk;
}
interface E15Report {
  campaign_id: string;
  generated_at_utc: string;
  sampling: { warmup: number; measured: number; sequential: boolean };
  device: { model?: string; os?: string; abi?: string; zygote?: string };
  apk: E15Apk;
  results: E15Result[];
}

const metadata: Record<
  Circuit,
  { variant: string; commit: string }
> = {
  passport: {
    variant: "passport_complete_age_check",
    commit: "",
  },
  webauthn: {
    variant: "webauthn_assertion",
    commit: "85aeeef539961cae5a63de794997b507a5975717",
  },
  oprf: {
    variant: "oprf_taceo",
    commit: "fd37726215b59d3d4823ea7b1967b1da3525ed9d",
  },
};

export function normalizeE15ProveKit(
  input: E15Report,
  sourceCommit: string,
  campaignId = input.campaign_id,
): AttemptRecord[] {
  if (
    input.sampling.warmup !== 1 ||
    input.sampling.measured !== 5 ||
    input.sampling.sequential !== true
  ) {
    throw new Error("E15 report violates the one-warmup/five-sequential-sample contract");
  }
  if (input.device.abi !== "armeabi-v7a" || input.device.zygote !== "zygote32") {
    throw new Error(
      `E15 report is not the canonical 32-bit target: ${input.device.abi}/${input.device.zygote}`,
    );
  }
  const records: AttemptRecord[] = [];
  for (const result of input.results) {
    const circuit = result.workload;
    const baseIdentity = metadata[circuit];
    const singleThreadPassport =
      circuit === "passport" && result.function.endsWith("_single_thread");
    const identity = {
      ...baseIdentity,
      variant: singleThreadPassport
        ? "passport_complete_age_check_single_thread"
        : baseIdentity.variant,
    };
    const common = {
      campaign_id: campaignId,
      recorded_at_utc: input.generated_at_utc,
      hardware: "motorola_e15" as const,
      device_model: input.device.model ?? "moto e15",
      os_version: `Android ${input.device.os ?? "14"}`,
      abi: input.device.abi,
      runtime: "android_native" as const,
      browser: "",
      circuit,
      circuit_variant: identity.variant,
      circuit_commit: identity.commit || sourceCommit,
      prover: "provekit_v1" as const,
      frontend: "noir",
      prover_backend: "provekit-v1-whir-native",
      witness_backend: "",
      initialization_time_ms: null,
      witness_time_ms: null,
      proof_size_bytes: null,
      circuit_size_bytes:
        result.report?.custom_metrics?.run_u64?.prover_size_bytes ?? null,
      artifact_size_bytes:
        result.report?.custom_metrics?.run_u64?.proving_payload_size_bytes ?? null,
      bundle_size_bytes:
        result.report?.custom_metrics?.run_u64?.proving_payload_size_bytes ?? null,
      constraint_count: null,
      artifact_version: "provekit-v1-native",
      source_commit: sourceCommit,
      package_versions: JSON.stringify({
        provekit: "v1",
        mobench_sdk: "0.1.48+e992596a786cc18047102a318d40131c953e57b8",
        mobench_cli: "0.1.48+e992596a786cc18047102a318d40131c953e57b8",
        ...(singleThreadPassport ? { rayon_threads: 1 } : {}),
      }),
      artifact_hashes: JSON.stringify({}),
      session_id: "",
      non_equivalence_note:
        "Closest available counterpart only; proof statements and implementation details are not equivalent.",
      evidence_path: result.evidence_path,
    };
    if (result.status !== "ok") {
      records.push({
        ...common,
        attempt_id: `motorola-e15-provekit-${identity.variant}-gap`,
        sample_kind: "gap",
        sample_index: null,
        status: result.status as Status,
        prover_time_ms: null,
        verify_time_ms: null,
        total_time_ms: null,
        peak_memory_mib: null,
        artifact_size_bytes: null,
        bundle_size_bytes: null,
        failure_code: result.failure?.kind ?? result.status,
        failure_detail:
          result.failure?.message ?? `E15 ${result.function} ended with ${result.status}`,
      });
      continue;
    }
    if (
      !result.report ||
      result.report.spec.warmup !== 1 ||
      result.report.spec.iterations !== 5 ||
      result.report.samples.length !== 5
    ) {
      throw new Error(`${result.function} does not contain five Mobench measured samples`);
    }
    const proveTimes = result.report.custom_metrics?.sample_u64?.prove_time_ns;
    const proofSizes = result.report.custom_metrics?.sample_u64?.proof_size_bytes;
    const expectedMetricCount =
      result.report.spec.warmup + result.report.spec.iterations;
    if (
      !proveTimes ||
      !proofSizes ||
      proveTimes.length !== expectedMetricCount ||
      proofSizes.length !== expectedMetricCount
    ) {
      throw new Error(
        `${result.function} is missing ${expectedMetricCount} prove_time_ns/proof_size_bytes custom metrics`,
      );
    }
    const provingPayloadSize =
      result.report.custom_metrics?.run_u64?.proving_payload_size_bytes;
    if (!Number.isInteger(provingPayloadSize) || provingPayloadSize! <= 0) {
      throw new Error(`${result.function} is missing proving_payload_size_bytes`);
    }
    records.push({
      ...common,
      attempt_id: `motorola-e15-provekit-${identity.variant}-warmup`,
      sample_kind: "warmup",
      sample_index: 0,
      status: "ok",
      prover_time_ms: null,
      verify_time_ms: null,
      total_time_ms: null,
      peak_memory_mib: null,
      failure_code: "",
      failure_detail: "",
    });
    result.report.samples.forEach((sample, index) => {
      const peakKb = sample.process_peak_memory_kb ?? sample.peak_memory_kb ?? null;
      const metricIndex = result.report!.spec.warmup + index;
      records.push({
        ...common,
        attempt_id: `motorola-e15-provekit-${identity.variant}-sample-${index + 1}`,
        sample_kind: "measured",
        sample_index: index + 1,
        status: "ok",
        prover_time_ms: proveTimes[metricIndex]! / 1_000_000,
        verify_time_ms: null,
        total_time_ms: sample.duration_ns / 1_000_000,
        peak_memory_mib: peakKb === null ? null : peakKb / 1024,
        proof_size_bytes: proofSizes[metricIndex]!,
        failure_code: "",
        failure_detail: "",
      });
    });
  }
  return validateAttempts(records, false);
}

if (import.meta.main) {
  const [inputPath, outputPath] = process.argv.slice(2);
  if (!inputPath || !outputPath) {
    console.error("usage: bun normalize-e15-provekit.ts <results.json> <attempts.json>");
    process.exit(2);
  }
  const input = (await Bun.file(inputPath).json()) as E15Report;
  const sourceCommit = process.env.CAMPAIGN_SOURCE_COMMIT ?? Bun.spawnSync(
    ["git", "rev-parse", "HEAD"],
    { cwd: resolve(import.meta.dir, "../../.."), stdout: "pipe" },
  ).stdout.toString().trim();
  const records = normalizeE15ProveKit(
    input,
    sourceCommit,
    process.env.CAMPAIGN_ID ?? input.campaign_id,
  );
  await Bun.write(outputPath, `${JSON.stringify(records, null, 2)}\n`);
  console.log(`wrote ${records.length} E15 ProveKit attempt records to ${outputPath}`);
}
