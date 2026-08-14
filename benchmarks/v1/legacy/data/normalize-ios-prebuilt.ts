#!/usr/bin/env bun

import { statSync } from "node:fs";
import { resolve } from "node:path";
import { validateAttempts } from "./export-benchmark-csv";
import type { AttemptRecord, Circuit, Prover, Status } from "./schema";

type Phase = "initialize" | "prove" | "verify" | "total";
interface Lane {
  circuit: Circuit;
  variant: string;
  circuitCommit: string;
  prover: Prover;
  proverBackend: string;
  witnessBackend: string;
  functions: Partial<Record<Phase, string>>;
}
interface Artifact {
  kind: string;
  path: string;
  size: number;
  sha256: string;
}
interface Entry {
  function: string;
  iterations: number;
  warmup: number;
  artifacts: Artifact[];
}
interface Manifest {
  source_sha: string;
  platform: string;
  entries: Entry[];
}
interface FunctionResult {
  spec?: { iterations?: number; warmup?: number };
  remote_run?: { build_id?: string };
  benchmark_results?: Record<string, BenchmarkResult[]>;
  performance_metrics?: Record<string, { memory?: { peak_mb?: number } }>;
}
interface BenchmarkResult {
  function?: string;
  samples?: unknown[];
  resources?: {
    process_peak_memory_kb?: number;
    peak_memory_kb?: number;
  };
  custom_metrics?: {
    sample_u64?: Record<string, number[]>;
    run_u64?: Record<string, number>;
  };
}
interface MergedSummary {
  functions?: Record<string, FunctionResult>;
}
interface GapEvidence {
  circuit: Circuit;
  prover: Prover;
  circuit_variant?: string;
  status: Exclude<Status, "ok">;
  failure_code: string;
  failure_detail: string;
  evidence_path: string;
  session_id?: string;
}

const WORLD_ID = "85aeeef539961cae5a63de794997b507a5975717";
const SELF = "15b167e3543a9dff1dbb16fcf71a45fe4625cf9e";
const WEBAUTHN_CIRCOM = "0fb5b4aa1398281c2fd3dbe14db147e05b61f201";
const TACEO_V1 = "808f3c795b57963dd58ef282ccd61022ef39c285";
const TACEO_V2 = "fd37726215b59d3d4823ea7b1967b1da3525ed9d";

export const IOS_LANES: Lane[] = [
  {
    circuit: "passport",
    variant: "passport_complete_age_check",
    circuitCommit: "",
    prover: "provekit_v1",
    proverBackend: "provekit-v1-whir-native",
    witnessBackend: "",
    functions: {
      prove: "bench_mobile::bench_passport_complete_age_check_prove",
    },
  },
  {
    circuit: "passport",
    variant: "passport_complete_age_check",
    circuitCommit: "",
    prover: "noir_barretenberg",
    proverBackend: "barretenberg-ultrahonk-native",
    witnessBackend: "",
    functions: {
      prove: "provekit_v1_mobile_adapters::bench_passport_barretenberg_prove",
    },
  },
  {
    circuit: "webauthn",
    variant: "webauthn_assertion",
    circuitCommit: WORLD_ID,
    prover: "provekit_v1",
    proverBackend: "provekit-v1-whir-native",
    witnessBackend: "",
    functions: {
      prove: "bench_mobile::bench_webauthn_assertion_prove",
    },
  },
  {
    circuit: "oprf",
    variant: "oprf_taceo",
    circuitCommit: TACEO_V2,
    prover: "provekit_v1",
    proverBackend: "provekit-v1-whir-native",
    witnessBackend: "",
    functions: {
      prove: "bench_mobile::bench_oprf_prove",
    },
  },
  {
    circuit: "webauthn",
    variant: "webauthn_assertion",
    circuitCommit: WORLD_ID,
    prover: "noir_barretenberg",
    proverBackend: "barretenberg-ultrahonk-native",
    witnessBackend: "",
    functions: {
      prove: "provekit_v1_mobile_adapters::bench_webauthn_barretenberg_prove",
    },
  },
  {
    circuit: "oprf",
    variant: "oprf_taceo",
    circuitCommit: TACEO_V1,
    prover: "noir_barretenberg",
    proverBackend: "barretenberg-ultrahonk-native",
    witnessBackend: "",
    functions: {
      prove: "provekit_v1_mobile_adapters::bench_oprf_barretenberg_prove",
    },
  },
  {
    circuit: "passport",
    variant: "self_vc_and_disclose",
    circuitCommit: SELF,
    prover: "circom_groth16",
    proverBackend: "rapidsnark-groth16-native",
    witnessBackend: "frozen-wtns-witnesscalc-adapter-0.1.7",
    functions: {
      prove: "provekit_v1_rapidsnark_mobile::bench_passport_rapidsnark_prove",
    },
  },
  {
    circuit: "passport",
    variant: "self_register_rsa_4096",
    circuitCommit: SELF,
    prover: "circom_groth16",
    proverBackend: "rapidsnark-groth16-native",
    witnessBackend: "frozen-wtns-witnesscalc-adapter-0.1.7",
    functions: {
      prove:
        "provekit_v1_rapidsnark_mobile_register::bench_passport_rapidsnark_prove",
    },
  },
  {
    circuit: "webauthn",
    variant: "privacy_ethereum_webauthn",
    circuitCommit: WEBAUTHN_CIRCOM,
    prover: "circom_groth16",
    proverBackend: "rapidsnark-groth16-native-single-thread",
    witnessBackend: "frozen-wtns-witnesscalc-adapter-0.1.7",
    functions: {
      prove:
        "provekit_v1_rapidsnark_mobile_webauthn::bench_webauthn_rapidsnark_prove",
    },
  },
  {
    circuit: "oprf",
    variant: "world_id_protocol_query",
    circuitCommit: WORLD_ID,
    prover: "circom_groth16",
    proverBackend: "rapidsnark-groth16-native",
    witnessBackend: "frozen-wtns-witnesscalc-adapter-0.1.7",
    functions: {
      prove:
        "provekit_v1_rapidsnark_mobile_oprf::bench_oprf_query_rapidsnark_prove",
    },
  },
  {
    circuit: "oprf",
    variant: "world_id_protocol_nullifier",
    circuitCommit: WORLD_ID,
    prover: "circom_groth16",
    proverBackend: "rapidsnark-groth16-native",
    witnessBackend: "frozen-wtns-witnesscalc-adapter-0.1.7",
    functions: {
      prove:
        "provekit_v1_rapidsnark_mobile_oprf::bench_oprf_nullifier_rapidsnark_prove",
    },
  },
];

function durationNs(sample: unknown): number {
  const value =
    typeof sample === "number"
      ? sample
      : sample && typeof sample === "object" && "duration_ns" in sample
        ? (sample as { duration_ns: unknown }).duration_ns
        : undefined;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new Error(`invalid Mobench duration sample: ${JSON.stringify(sample)}`);
  }
  return value;
}

function processPeakMemoryKib(sample: unknown): number | null {
  if (!sample || typeof sample !== "object") return null;
  const value =
    "process_peak_memory_kb" in sample
      ? (sample as { process_peak_memory_kb: unknown }).process_peak_memory_kb
      : "peak_memory_kb" in sample
        ? (sample as { peak_memory_kb: unknown }).peak_memory_kb
        : undefined;
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? value
    : null;
}

function samplesFor(result: FunctionResult, functionName: string, device: string): number[] {
  return benchmarkResultFor(result, functionName, device).samples!.map(durationNs);
}

function benchmarkResultFor(
  result: FunctionResult,
  functionName: string,
  device: string,
): BenchmarkResult {
  const entries = result.benchmark_results?.[device];
  if (!entries) throw new Error(`${functionName}: missing benchmark_results for ${device}`);
  const entry = entries.find((candidate) => candidate.function === functionName) ?? entries[0];
  if (!entry?.samples || entry.samples.length !== 5) {
    throw new Error(
      `${functionName}: expected five measured samples, found ${entry?.samples?.length ?? 0}`,
    );
  }
  return entry;
}

export function normalizeIosPrebuilt(
  summary: MergedSummary,
  manifest: Manifest,
  options: {
    campaignId: string;
    sourceCommit: string;
    device: string;
    osVersion: string;
    evidencePath: string;
    recordedAtUtc: string;
    gaps?: GapEvidence[];
  },
): AttemptRecord[] {
  if (manifest.platform !== "ios") throw new Error(`expected ios manifest, found ${manifest.platform}`);
  const functions = summary.functions ?? {};
  const entries = new Map(manifest.entries.map((entry) => [entry.function, entry]));
  const records: AttemptRecord[] = [];

  for (const lane of IOS_LANES) {
    const phaseSamples = new Map<Phase, number[]>();
    const names = new Set(Object.values(lane.functions));
    const missingNames = [...names].filter(
      (name) => !functions[name] || !entries.has(name),
    );
    if (missingNames.length) {
      const gap = options.gaps?.find(
        (candidate) =>
          candidate.circuit === lane.circuit &&
          candidate.prover === lane.prover &&
          (!candidate.circuit_variant ||
            candidate.circuit_variant === lane.variant),
      );
      if (!gap) {
        throw new Error(
          `missing iOS result or manifest entry: ${missingNames.join(", ")}`,
        );
      }
      records.push({
        campaign_id: options.campaignId,
        attempt_id: `iphone-se-2022-${lane.prover}-${lane.variant}-gap`,
        recorded_at_utc: options.recordedAtUtc,
        hardware: "iphone_se_2022",
        device_model: "iPhone SE 2022",
        os_version: options.osVersion,
        abi: "arm64",
        runtime: "ios_native",
        browser: "",
        circuit: lane.circuit,
        circuit_variant: lane.variant,
        circuit_commit: lane.circuitCommit || options.sourceCommit,
        prover: lane.prover,
        frontend: lane.prover === "circom_groth16" ? "circom" : "noir",
        prover_backend: lane.proverBackend,
        witness_backend: lane.witnessBackend,
        sample_kind: "gap",
        sample_index: null,
        status: gap.status,
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
        artifact_version:
          lane.prover === "provekit_v1"
            ? "provekit-v1-native"
            : lane.prover === "noir_barretenberg"
              ? "noir-v1.0.0-beta.19-barretenberg-rs-4.2.0-aztecnr-rc.2"
              : "groth16-rust-rapidsnark-0.1.4",
        source_commit: options.sourceCommit,
        package_versions: JSON.stringify(
          lane.prover === "provekit_v1"
            ? { provekit: "v1" }
            : lane.prover === "noir_barretenberg"
              ? {
                  mopro: "0.3.7",
                  noir: "1.0.0-beta.19",
                  barretenberg_rs: "4.2.0-aztecnr-rc.2",
                }
              : {
                  mopro: "0.3.7",
                  rust_rapidsnark: "0.1.4",
                  witnesscalc_adapter: "0.1.7",
                  ...(lane.variant === "privacy_ethereum_webauthn"
                    ? { rapidsnark_threads: 1 }
                    : {}),
                },
        ),
        artifact_hashes: JSON.stringify({}),
        session_id: gap.session_id ?? "",
        non_equivalence_note:
          "Closest available counterpart only; proof statements and implementation details are not equivalent.",
        failure_code: gap.failure_code,
        failure_detail: gap.failure_detail,
        evidence_path: resolve(gap.evidence_path),
      });
      continue;
    }
    for (const [phase, name] of Object.entries(lane.functions) as [Phase, string][]) {
      const result = functions[name];
      const entry = entries.get(name);
      if (!result || !entry) throw new Error(`missing iOS result or manifest entry: ${name}`);
      if (entry.warmup !== 1 || entry.iterations !== 5) {
        throw new Error(`${name}: manifest violates the one-warmup/five-sample contract`);
      }
      if (result.spec?.warmup !== 1 || result.spec?.iterations !== 5) {
        throw new Error(`${name}: result spec violates the one-warmup/five-sample contract`);
      }
      phaseSamples.set(phase, samplesFor(result, name, options.device));
    }

    // IPA and XCUITest uploads are transport containers, not proving inputs.
    // Input hashes remain blank until the frozen proving files are reported
    // directly rather than inferred from duplicate uploaded bundles.
    const artifactHashes = {};
    const proveFunction = lane.functions.prove;
    const proveResult = proveFunction ? functions[proveFunction] : undefined;
    const proveReport =
      proveFunction && proveResult
        ? benchmarkResultFor(proveResult, proveFunction, options.device)
        : undefined;
    const customMetrics = proveReport?.custom_metrics;
    const proofSizes = customMetrics?.sample_u64?.proof_size_bytes;
    const proveTimes = customMetrics?.sample_u64?.prove_time_ns;
    const provingPayloadSize =
      customMetrics?.run_u64?.proving_payload_size_bytes ?? null;
    // The campaign's reader-facing "circuit size" metric means every frozen
    // input needed to create a proof. For iPhone Circom lanes the retained
    // asset inventory is zkey + WTNS, so use its reported aggregate rather
    // than the zkey-only value.
    const circuitSize =
      lane.prover === "circom_groth16" &&
      customMetrics?.run_u64?.zkey_size_bytes !== undefined
        ? provingPayloadSize
        : customMetrics?.run_u64?.circuit_size_bytes ??
          customMetrics?.run_u64?.prover_size_bytes ??
          null;
    if (
      !proofSizes ||
      proofSizes.length !== 6 ||
      !proveTimes ||
      proveTimes.length !== 6 ||
      !Number.isInteger(provingPayloadSize) ||
      provingPayloadSize! <= 0
    ) {
      throw new Error(
        `${proveFunction}: missing exact prove_time_ns, proof_size_bytes, or proving_payload_size_bytes custom metrics`,
      );
    }
    const sessionIds = [...names]
      .map((name) => functions[name]?.remote_run?.build_id)
      .filter((value): value is string => Boolean(value));
    const peakMemory = [...names]
      .map((name) => functions[name]?.performance_metrics?.[options.device]?.memory?.peak_mb)
      .filter((value): value is number => typeof value === "number");
    const proveResourcePeakKib =
      proveReport?.resources?.process_peak_memory_kb ??
      proveReport?.resources?.peak_memory_kb ??
      null;
    const fallbackPeakMemoryMib =
      proveResourcePeakKib !== null
        ? proveResourcePeakKib / 1024
        : peakMemory.length
          ? Math.max(...peakMemory)
          : null;
    const common = {
      campaign_id: options.campaignId,
      recorded_at_utc: options.recordedAtUtc,
      hardware: "iphone_se_2022" as const,
      device_model: "iPhone SE 2022",
      os_version: options.osVersion,
      abi: "arm64",
      runtime: "ios_native" as const,
      browser: "",
      circuit: lane.circuit,
      circuit_variant: lane.variant,
      circuit_commit: lane.circuitCommit || options.sourceCommit,
      prover: lane.prover,
      frontend: lane.prover === "circom_groth16" ? "circom" : "noir",
      prover_backend: lane.proverBackend,
      witness_backend: lane.witnessBackend,
      initialization_time_ms: null,
      witness_time_ms: null,
      peak_memory_mib: null,
      proof_size_bytes: null,
      circuit_size_bytes: circuitSize,
      artifact_size_bytes: provingPayloadSize,
      bundle_size_bytes: provingPayloadSize,
      constraint_count: null,
      artifact_version:
        lane.prover === "provekit_v1"
          ? "provekit-v1-native"
          : lane.prover === "noir_barretenberg"
            ? "noir-v1.0.0-beta.19-barretenberg-rs-4.2.0-aztecnr-rc.2"
            : "groth16-rust-rapidsnark-0.1.4",
      source_commit: options.sourceCommit,
      package_versions: JSON.stringify(
        lane.prover === "provekit_v1"
          ? { provekit: "v1" }
          : lane.prover === "noir_barretenberg"
            ? {
                mopro: "0.3.7",
                noir: "1.0.0-beta.19",
                barretenberg_rs: "4.2.0-aztecnr-rc.2",
              }
            : {
                mopro: "0.3.7",
                rust_rapidsnark: "0.1.4",
                witnesscalc_adapter: "0.1.7",
                ...(lane.variant === "privacy_ethereum_webauthn"
                  ? { rapidsnark_threads: 1 }
                  : {}),
              },
      ),
      artifact_hashes: JSON.stringify(artifactHashes),
      session_id: sessionIds.join(";"),
      non_equivalence_note:
        lane.prover === "circom_groth16"
          ? "Closest available counterpart only; proof statements and implementation details are not equivalent. Circuit/proving payload size is an asset-size estimate: zkey plus frozen WTNS; IPA and app package sizes are excluded."
          : "Closest available counterpart only; proof statements and implementation details are not equivalent.",
      failure_code: "",
      failure_detail: "",
      evidence_path: options.evidencePath,
    };

    records.push({
      ...common,
      attempt_id: `iphone-se-2022-${lane.prover}-${lane.variant}-warmup`,
      sample_kind: "warmup",
      sample_index: 0,
      status: "ok",
      initialization_time_ms: null,
      prover_time_ms: null,
      verify_time_ms: null,
      total_time_ms: null,
    });
    for (let index = 0; index < 5; index++) {
      const proveNs = proveTimes[index + 1]!;
      const verifyNs = phaseSamples.get("verify")?.[index];
      // For proof-only campaigns this is the Mobench wrapper duration for the
      // prove function, while prover_time_ms remains the adapter's internal
      // prover call. It is not presented as a full witness+prove+verify e2e.
      const totalNs = phaseSamples.get("total")?.[index] ??
        phaseSamples.get("prove")![index]!;
      const samplePeakKib = processPeakMemoryKib(proveReport?.samples?.[index]);
      records.push({
        ...common,
        attempt_id: `iphone-se-2022-${lane.prover}-${lane.variant}-sample-${index + 1}`,
        sample_kind: "measured",
        sample_index: index + 1,
        status: "ok",
        initialization_time_ms:
          phaseSamples.get("initialize")?.[index] === undefined
            ? null
            : phaseSamples.get("initialize")![index]! / 1_000_000,
        prover_time_ms: proveNs / 1_000_000,
        verify_time_ms: verifyNs === undefined ? null : verifyNs / 1_000_000,
        total_time_ms: totalNs / 1_000_000,
        peak_memory_mib:
          samplePeakKib === null ? fallbackPeakMemoryMib : samplePeakKib / 1024,
        proof_size_bytes: proofSizes[index + 1]!,
      });
    }
  }
  return validateAttempts(records, false);
}

function usage(): never {
  console.error(
    "usage: bun normalize-ios-prebuilt.ts <summary.json> <manifest.json> <attempts.json> <source-commit> [device] [os-version] [gaps.json]",
  );
  process.exit(2);
}

if (import.meta.main) {
  const [
    summaryPath,
    manifestPath,
    outputPath,
    sourceCommit,
    device = "iPhone SE 2022-15",
    osVersion = "iOS 15",
    gapsPath,
  ] = process.argv.slice(2);
  if (
    !summaryPath ||
    !manifestPath ||
    !outputPath ||
    !sourceCommit ||
    !/^[0-9a-f]{40}$/.test(sourceCommit)
  ) {
    usage();
  }
  const summary = (await Bun.file(summaryPath).json()) as MergedSummary;
  const manifest = (await Bun.file(manifestPath).json()) as Manifest;
  const gaps = gapsPath
    ? ((await Bun.file(gapsPath).json()) as GapEvidence[])
    : undefined;
  const records = normalizeIosPrebuilt(summary, manifest, {
    campaignId: process.env.CAMPAIGN_ID ?? "provekit-v1-cross-device-20260729",
    sourceCommit,
    device,
    osVersion,
    evidencePath: resolve(summaryPath),
    recordedAtUtc: statSync(summaryPath).mtime.toISOString(),
    gaps,
  });
  await Bun.write(outputPath, `${JSON.stringify(records, null, 2)}\n`);
  console.log(`wrote ${records.length} iOS attempt records to ${outputPath}`);
}
