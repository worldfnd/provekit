#!/usr/bin/env bun

import { dirname, join, resolve } from "node:path";
import {
  type BenchResult,
  isSha256,
  isSourceSha,
  verifyBenchContract,
  writeJsonAtomic,
} from "./android-appium-evidence";

type JsonObject = Record<string, unknown>;

const expectedFunctions = [
  "bench_mobile::bench_passport_complete_age_check_prepare",
  "bench_mobile::bench_passport_complete_age_check_prove",
  "bench_mobile::bench_passport_complete_age_check_verify",
  "bench_mobile::bench_passport_complete_age_check_e2e",
  "bench_mobile::bench_webauthn_assertion_prepare",
  "bench_mobile::bench_webauthn_assertion_prove",
  "bench_mobile::bench_webauthn_assertion_verify",
  "bench_mobile::bench_webauthn_assertion_e2e",
  "bench_mobile::bench_oprf_prepare",
  "bench_mobile::bench_oprf_prove",
  "bench_mobile::bench_oprf_verify",
  "bench_mobile::bench_oprf_e2e",
] as const;

function asObject(value: unknown, name: string): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as JsonObject;
}

function numericSamples(
  report: BenchResult,
  field: "cpu_time_ms" | "process_peak_memory_kb",
): number[] {
  return report.samples.flatMap((sample) => {
    const value = sample[field];
    return typeof value === "number" && Number.isFinite(value) ? [value] : [];
  });
}

function median(values: number[]): number {
  if (values.length === 0) throw new Error("cannot compute an empty median");
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.floor(sorted.length / 2)]!;
}

async function main(): Promise<void> {
  const outputDir = resolve(Bun.argv[2] ?? "");
  if (!Bun.argv[2]) {
    throw new Error(
      "usage: bun benchmarks/v1/scripts/summarize-android-appium-release.ts OUTPUT_DIR",
    );
  }
  const indexPath = join(outputDir, "index.json");
  const index = asObject(await Bun.file(indexPath).json(), "index");
  if (
    index.schema !== "provekit.android-browserstack-appium-shards.v1" ||
    !isSourceSha(index.source_sha) ||
    !Array.isArray(index.shards)
  ) {
    throw new Error("invalid Android Appium shard index");
  }

  const byFunction = new Map<string, JsonObject>();
  for (const rawStatus of index.shards) {
    const status = asObject(rawStatus, "shard status");
    if (
      status.outcome !== "success" ||
      typeof status.function !== "string" ||
      typeof status.device !== "string"
    ) {
      continue;
    }
    if (status.device !== "Google Pixel 7-13.0") continue;
    if (byFunction.has(status.function)) {
      throw new Error(`duplicate successful shard: ${status.function}`);
    }
    byFunction.set(status.function, status);
  }

  const missing = expectedFunctions.filter((name) => !byFunction.has(name));
  if (missing.length > 0) {
    throw new Error(`release matrix is incomplete: ${missing.join(", ")}`);
  }

  const rows: JsonObject[] = [];
  for (const functionName of expectedFunctions) {
    const status = byFunction.get(functionName)!;
    if (
      status.source_sha !== index.source_sha ||
      !isSha256(status.artifact_sha256) ||
      typeof status.bench_report !== "string" ||
      typeof status.result !== "string" ||
      typeof status.session_id !== "string" ||
      typeof status.build_id !== "string"
    ) {
      throw new Error(`${functionName} status lacks publication identity`);
    }
    const reportPath = resolve(outputDir, status.bench_report);
    const resultPath = resolve(outputDir, status.result);
    const shardDir = dirname(reportPath);
    const report = (await Bun.file(reportPath).json()) as BenchResult;
    const identity = asObject(await Bun.file(resultPath).json(), "result");
    const request = asObject(
      await Bun.file(join(shardDir, "request.json")).json(),
      "request",
    );
    const upload = asObject(
      await Bun.file(join(shardDir, "upload.json")).json(),
      "upload",
    );
    const uploadArtifact = asObject(upload.artifact, "upload artifact");
    verifyBenchContract(report, functionName);
    if (
      identity.source_sha !== index.source_sha ||
      identity.function !== functionName ||
      identity.artifact_sha256 !== status.artifact_sha256 ||
      identity.artifact_build_profile !== "release" ||
      identity.measured_samples !== 5 ||
      identity.warmup !== 1
    ) {
      throw new Error(`${functionName} result identity mismatch`);
    }
    if (
      request.source_sha !== index.source_sha ||
      !isSha256(request.source_manifest_sha256) ||
      request.artifact_sha256 !== status.artifact_sha256 ||
      request.artifact_build_profile !== "release" ||
      request.signed !== true ||
      upload.source_sha !== index.source_sha ||
      upload.function !== functionName ||
      uploadArtifact.sha256 !== status.artifact_sha256 ||
      !Number.isSafeInteger(uploadArtifact.bytes) ||
      (uploadArtifact.bytes as number) <= 0 ||
      uploadArtifact.build_profile !== "release" ||
      uploadArtifact.signed !== true ||
      !isSha256(uploadArtifact.embedded_native_library_sha256) ||
      !isSha256(uploadArtifact.embedded_bench_spec_sha256)
    ) {
      throw new Error(`${functionName} request/upload provenance mismatch`);
    }
    const samples = report.samples_ns;
    const cpu = numericSamples(report, "cpu_time_ms");
    const processPeak = numericSamples(report, "process_peak_memory_kb");
    rows.push({
      function: functionName,
      device: status.device,
      source_sha: index.source_sha,
      artifact_sha256: status.artifact_sha256,
      artifact_bytes: uploadArtifact.bytes,
      embedded_native_library_sha256:
        uploadArtifact.embedded_native_library_sha256,
      embedded_bench_spec_sha256: uploadArtifact.embedded_bench_spec_sha256,
      source_manifest_sha256: request.source_manifest_sha256,
      session_id: status.session_id,
      build_id: status.build_id,
      warmup: 1,
      measured_samples: 5,
      samples_ns: samples,
      median_ns: median(samples),
      mean_ns: samples.reduce((sum, value) => sum + value, 0) / samples.length,
      min_ns: Math.min(...samples),
      max_ns: Math.max(...samples),
      median_cpu_time_ms: cpu.length === 5 ? median(cpu) : null,
      max_process_peak_memory_kb:
        processPeak.length === 5 ? Math.max(...processPeak) : null,
      bench_report: status.bench_report,
    });
  }

  await writeJsonAtomic(join(outputDir, "summary.json"), {
    schema: "provekit.android-appium-release-summary.v1",
    generated_at: new Date().toISOString(),
    source_sha: index.source_sha,
    device: "Google Pixel 7",
    os_version: "13.0",
    control_plane: "BrowserStack App Automate + Appium/UiAutomator2",
    wrapper: "signed release AAB",
    contract: { warmup: 1, measured_samples: 5 },
    expected_functions: expectedFunctions.length,
    completed_functions: rows.length,
    publication_gate: {
      exact_source: true,
      release_wrapper: true,
      function_isolated: true,
      valid_proof_verification: true,
      tampered_proof_rejected_by_retained_host_gate: true,
    },
    rows,
    source_index: "index.json",
    evidence_root: ".",
  });
}

await main();
