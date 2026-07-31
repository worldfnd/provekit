#!/usr/bin/env bun

import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { toCsv, validateAttempts } from "../data/export-benchmark-csv";
import { CSV_COLUMNS, type AttemptRecord, type CsvColumn } from "../data/schema";

const root = resolve(import.meta.dir);
const csvPath = resolve(root, "semantic-parity-samples.csv");
const manifestPath = resolve(root, "manifest.json");
const numericColumns = new Set<CsvColumn>([
  "initialization_time_ms", "witness_time_ms", "prover_time_ms", "verify_time_ms",
  "total_time_ms", "peak_memory_mib", "proof_size_bytes", "circuit_size_bytes",
  "artifact_size_bytes", "bundle_size_bytes", "constraint_count", "sample_index",
]);

type ManifestCell = {
  cell_id: string;
  profile: string;
  target: string;
  stack: string;
  state: string;
  evidence: string;
  evidence_sha256: string;
  payload: Array<{ name?: string; bytes: number; sha256: string }>;
  provenance?: { session_id?: string };
};

type Manifest = {
  campaign_id: string;
  provekit_v1: {
    core_commit: string;
    campaign_harness_commit: string;
    noir_version: string;
  };
  cells: ManifestCell[];
};

function parseCsv(text: string): Record<string, string>[] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (quoted) {
      if (char === '"' && text[i + 1] === '"') { field += '"'; i += 1; }
      else if (char === '"') quoted = false;
      else field += char;
    } else if (char === '"' && field === "") quoted = true;
    else if (char === ",") { row.push(field); field = ""; }
    else if (char === "\n") { row.push(field.replace(/\r$/, "")); rows.push(row); row = []; field = ""; }
    else field += char;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  const header = rows.shift() ?? [];
  return rows.filter((candidate) => candidate.some(Boolean)).map((candidate) =>
    Object.fromEntries(header.map((column, index) => [column, candidate[index] ?? ""])),
  );
}

function attemptsFromCsv(text: string): AttemptRecord[] {
  return parseCsv(text).map((raw) => {
    const record: Record<string, unknown> = { ...raw };
    for (const column of numericColumns) record[column] = raw[column] === "" ? null : Number(raw[column]);
    return record as AttemptRecord;
  });
}

async function sha256(path: string): Promise<string> {
  return createHash("sha256").update(Buffer.from(await Bun.file(path).arrayBuffer())).digest("hex");
}

function json(value: unknown): string {
  return JSON.stringify(value);
}

function workloadFor(profile: string): "passport" | "webauthn" | "oprf" {
  if (profile === "passport_p1") return "passport";
  if (profile === "webauthn_closest_analogue") return "webauthn";
  if (profile === "oprf_o2") return "oprf";
  throw new Error(`unknown ProveKit V1 profile ${profile}`);
}

function circuitCommit(profile: string, coreCommit: string): string {
  if (profile === "passport_p1") return coreCommit;
  if (profile === "webauthn_closest_analogue") return "85aeeef539961cae5a63de794997b507a5975717";
  return "fd37726215b59d3d4823ea7b1967b1da3525ed9d";
}

function hardware(target: string): AttemptRecord["hardware"] {
  if (target === "mac_chrome") return "macbook_m4";
  if (target === "iphone_se_2022") return "iphone_se_2022";
  if (target === "motorola_e15") return "motorola_e15";
  throw new Error(`unknown target ${target}`);
}

function device(target: string) {
  if (target === "mac_chrome") return { model: "MacBook Pro M4 Max", os: "macOS 26.5.2 (25F84)", abi: "arm64", runtime: "browser_wasm" as const, browser: "Google Chrome 151.0.7922.72 (headless)" };
  if (target === "iphone_se_2022") return { model: "iPhone SE 2022", os: "iOS 15", abi: "arm64", runtime: "ios_native" as const, browser: "" };
  return { model: "moto e15", os: "Android 14", abi: "armeabi-v7a", runtime: "android_native" as const, browser: "" };
}

function payloadSize(cell: ManifestCell): number {
  const size = (cell.payload ?? []).reduce((sum, component) => sum + component.bytes, 0);
  if (!Number.isSafeInteger(size) || size <= 0) throw new Error(`${cell.cell_id}: invalid proving payload size`);
  return size;
}

function hashes(cell: ManifestCell): string {
  return json({
    evidence: cell.evidence_sha256,
    payload: Object.fromEntries((cell.payload ?? []).map((component) => [component.name ?? "payload", component.sha256])),
  });
}

function common(cell: ManifestCell, manifest: Manifest, evidencePath: string, circuit: string, payload: number): Omit<AttemptRecord, "attempt_id" | "sample_kind" | "sample_index" | "status" | "initialization_time_ms" | "witness_time_ms" | "prover_time_ms" | "verify_time_ms" | "total_time_ms" | "peak_memory_mib" | "proof_size_bytes" | "failure_code" | "failure_detail"> {
  const target = device(cell.target);
  const core = manifest.provekit_v1.core_commit;
  return {
    campaign_id: manifest.campaign_id,
    recorded_at_utc: "2026-07-31T00:00:00Z",
    hardware: hardware(cell.target),
    device_model: target.model,
    os_version: target.os,
    abi: target.abi,
    runtime: target.runtime,
    browser: target.browser,
    circuit,
    circuit_variant: cell.profile,
    circuit_commit: circuitCommit(cell.profile, core),
    prover: "provekit_v1",
    frontend: "noir",
    prover_backend: cell.target === "mac_chrome" ? "provekit-v1-branch-9b2a6f3-wasm-single" : "provekit-v1-whir-native",
    witness_backend: `noir-v${manifest.provekit_v1.noir_version}`,
    circuit_size_bytes: payload,
    artifact_size_bytes: payload,
    bundle_size_bytes: payload,
    constraint_count: null,
    artifact_version: `provekit-v1-core-${core.slice(0, 7)}-noir-beta.11`,
    source_commit: core,
    package_versions: json({ provekit_core: core, noir: manifest.provekit_v1.noir_version, mobench: "0.1.48", campaign_harness: manifest.provekit_v1.campaign_harness_commit }),
    artifact_hashes: hashes(cell),
    session_id: cell.provenance?.session_id ?? "",
    non_equivalence_note: "Closest available semantic counterpart; Noir and Circom statements remain non-equivalent where noted by the campaign. ProveKit V1 measurements use the pinned core WASM/C-ABI build, not @worldcoin/provekit npm artifacts. Browser proof_size_bytes is V1 WASM proof-byte serialization; native proof_size_bytes is serialized postcard NoirProof (.np) bytes.",
    evidence_path: evidencePath,
  };
}

function rowsFromSamples(cell: ManifestCell, manifest: Manifest, report: any, evidencePath: string, samples: Array<{ warmup: boolean; index: number; proveMs: number; totalMs: number; proofBytes: number; memoryMib: number }>) {
  const payload = payloadSize(cell);
  const base = common(cell, manifest, evidencePath, workloadFor(cell.profile), payload);
  const rows: AttemptRecord[] = [];
  rows.push({ ...base, attempt_id: `${cell.cell_id}__warmup`, sample_kind: "warmup", sample_index: 0, status: "ok", initialization_time_ms: null, witness_time_ms: null, prover_time_ms: null, verify_time_ms: null, total_time_ms: null, peak_memory_mib: null, proof_size_bytes: null, failure_code: "", failure_detail: "" });
  for (const sample of samples.filter((candidate) => !candidate.warmup)) {
    rows.push({ ...base, attempt_id: `${cell.cell_id}__sample-${sample.index}`, sample_kind: "measured", sample_index: sample.index, status: "ok", initialization_time_ms: null, witness_time_ms: null, prover_time_ms: sample.proveMs, verify_time_ms: null, total_time_ms: sample.totalMs, peak_memory_mib: sample.memoryMib, proof_size_bytes: sample.proofBytes, failure_code: "", failure_detail: "" });
  }
  return rows;
}

function macRows(cell: ManifestCell, manifest: Manifest, report: any): AttemptRecord[] {
  const peakMib = report.process_memory.peak_rss_kib / 1024;
  return rowsFromSamples(cell, manifest, report, cell.evidence, report.samples.map((sample: any) => ({
    warmup: sample.warmup,
    index: sample.warmup ? 0 : sample.iteration + 1,
    proveMs: sample.prove_time_ms,
    totalMs: sample.end_to_end_time_ms,
    proofBytes: sample.proof_size_bytes,
    memoryMib: peakMib,
  })));
}

function nativeRows(cell: ManifestCell, manifest: Manifest, report: any): AttemptRecord[] {
  const custom = report.custom_metrics;
  const prove = custom.sample_u64.prove_time_ns as number[];
  const proofs = custom.sample_u64.proof_size_bytes as number[];
  const sourceSamples = report.samples as any[];
  return rowsFromSamples(cell, manifest, report, cell.evidence, sourceSamples.map((sample: any, index: number) => ({
    warmup: false,
    index: index + 1,
    proveMs: prove[index + 1] / 1e6,
    totalMs: sample.duration_ns / 1e6,
    proofBytes: proofs[index + 1],
    memoryMib: sample.process_peak_memory_kb / 1024,
  })).concat([{ warmup: true, index: 0, proveMs: 0, totalMs: 0, proofBytes: 0, memoryMib: 0 }]));
}

function evidenceForCell(cell: ManifestCell, manifest: Manifest): any {
  const path = resolve(root, cell.evidence);
  return Bun.file(path).json();
}

async function replaceV1Rows(): Promise<AttemptRecord[]> {
  const manifest = await Bun.file(manifestPath).json() as Manifest;
  const base = attemptsFromCsv(await Bun.file(csvPath).text()).filter((row) => row.prover !== "provekit_v1");
  const v1Rows: AttemptRecord[] = [];
  for (const cell of manifest.cells.filter((candidate) => candidate.stack === "provekit_v1")) {
    const evidencePath = resolve(root, cell.evidence);
    if (await sha256(evidencePath) !== cell.evidence_sha256) throw new Error(`${cell.cell_id}: evidence hash drift`);
    const raw = await evidenceForCell(cell, manifest);
    if (cell.target === "mac_chrome") {
      v1Rows.push(...macRows(cell, manifest, raw));
      continue;
    }
    if (cell.target === "iphone_se_2022") {
      const fn = cell.profile === "passport_p1" ? "bench_mobile::bench_passport_complete_age_check_prove" : cell.profile === "oprf_o2" ? "bench_mobile::bench_oprf_prove" : "bench_mobile::bench_webauthn_assertion_prove";
      const report = raw.functions[fn].benchmark_results["iPhone SE 2022-15"][0];
      v1Rows.push(...nativeRows(cell, manifest, report));
      continue;
    }
    const report = raw.results.find((result: any) => result.workload === workloadFor(cell.profile))?.report;
    if (!report) throw new Error(`${cell.cell_id}: native report missing`);
    v1Rows.push(...nativeRows(cell, manifest, report));
  }
  return validateAttempts([...base, ...v1Rows], true);
}

export async function exportV1(output = csvPath): Promise<AttemptRecord[]> {
  const rows = await replaceV1Rows();
  await Bun.write(output, toCsv(rows));
  return rows;
}

if (import.meta.main) {
  const outputFlag = Bun.argv.find((arg) => arg.startsWith("--output="));
  const output = resolve(outputFlag?.slice("--output=".length) ?? csvPath);
  const rows = await exportV1(output);
  console.log(JSON.stringify({ output, rows: rows.length, cells: new Set(rows.map((row) => `${row.hardware}|${row.circuit}|${row.prover}`)).size, successful_cells: new Set(rows.filter((row) => row.status === "ok").map((row) => `${row.hardware}|${row.circuit}|${row.prover}`)).size }, null, 2));
}
