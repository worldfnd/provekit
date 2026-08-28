#!/usr/bin/env bun

import { createHash } from "node:crypto";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "../../..");
const csvPath = resolve(process.env.INPUT_TO_PROOF_OUTPUT_CSV ?? import.meta.dir + "/input-to-proof-samples.csv");
const taceoRoot = resolve(root, "target/v1-benchmarks/taceo-v021");
const campaignId = "input-to-proof-v1-taceo-oprf-20260814";
const circuitCommit = "85aeeef539961cae5a63de794997b507a5975717";
const helpersCommit = "8aacd73ed6ab0a2b9b2158e613acfa920860865a";
const witnessCommit = "e11206a9f453145dcd6b814523cbfba4f60cf5c6";
const serial = "ZY32M6782K";

type Row = Record<string, string>;
type Sample = {
  warmup: boolean;
  initialization: number;
  witness: number;
  prove: number;
  verify: number;
  total: number;
  peak: number | null;
  proof: number;
};

function parseCsv(text: string): { columns: string[]; rows: Row[] } {
  const records: string[][] = [];
  let record: string[] = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') {
        field += '"';
        index += 1;
      } else if (char === '"') {
        quoted = false;
      } else {
        field += char;
      }
    } else if (char === '"' && field.length === 0) {
      quoted = true;
    } else if (char === ",") {
      record.push(field);
      field = "";
    } else if (char === "\n") {
      record.push(field.endsWith("\r") ? field.slice(0, -1) : field);
      records.push(record);
      record = [];
      field = "";
    } else {
      field += char;
    }
  }
  if (field.length > 0 || record.length > 0) {
    record.push(field);
    records.push(record);
  }
  const [columns, ...values] = records;
  if (!columns?.length) throw new Error("CSV has no header");
  return {
    columns,
    rows: values.filter((value) => value.length > 1).map((value) =>
      Object.fromEntries(columns.map((column, index) => [column, value[index] ?? ""])),
    ),
  };
}

function csvValue(value: string): string {
  return /[",\n\r]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
}

async function json(path: string): Promise<any> {
  return Bun.file(path).json();
}

async function sha256(path: string): Promise<string> {
  const bytes = await Bun.file(path).arrayBuffer();
  return createHash("sha256").update(Buffer.from(bytes)).digest("hex");
}

const assets = {
  zkey: resolve(root, "benchmarks/v1/circom/taceo-mobile/assets/OPRFNullifier.arks.zkey"),
  graph: resolve(root, "target/v1-benchmarks/taceo-v021/generated/OPRFNullifierGraph.bin"),
  input: resolve(root, "benchmarks/v1/circom/taceo-mobile/assets/oprf_nullifier.input.json"),
};
const [zkeySize, graphSize, inputSize, zkeyHash, graphHash, inputHash] = await Promise.all([
  Bun.file(assets.zkey).size,
  Bun.file(assets.graph).size,
  Bun.file(assets.input).size,
  sha256(assets.zkey),
  sha256(assets.graph),
  sha256(assets.input),
]);
const artifactSize = zkeySize + graphSize;
const payloadSize = artifactSize + inputSize;

function required(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`missing ${label}`);
  return value;
}

function sampleFromNative(value: any): Sample {
  if (value.status !== "ok" || value.valid_proof_accepted !== true || value.tampered_proof_rejected !== true) {
    throw new Error("TACEO native evidence did not pass proof/tamper gates");
  }
  return {
    warmup: Boolean(value.warmup),
    initialization: required(value.initialization_time_ms, "initialization_time_ms"),
    witness: required(value.witness_time_ms, "witness_time_ms"),
    prove: required(value.prover_time_ms, "prover_time_ms"),
    verify: required(value.verify_time_ms, "verify_time_ms"),
    total: required(value.input_to_proof_time_ms, "input_to_proof_time_ms"),
    peak: required(value.peak_memory_mib, "peak_memory_mib"),
    proof: required(value.proof_size_bytes, "proof_size_bytes"),
  };
}

function customSample(report: any, index: number, warmup: boolean, resourceIndex: number | null): Sample {
  const values = report.custom_metrics?.sample_u64 ?? {};
  const value = (name: string) => required(values[name]?.[index], `${name}[${index}]`) / 1e6;
  const proof = required(values.proof_size_bytes?.[index], `proof_size_bytes[${index}]`);
  const resource = resourceIndex == null ? null : report.samples?.[resourceIndex];
  return {
    warmup,
    initialization: value("initialization_time_ns"),
    witness: value("witness_time_ns"),
    prove: value("prove_time_ns"),
    verify: value("verify_time_ns"),
    total: value("input_to_proof_time_ns"),
    peak: resource?.process_peak_memory_kb == null ? null : resource.process_peak_memory_kb / 1024,
    proof,
  };
}

type Evidence = {
  target: "macbook_m4" | "iphone_se_2022" | "motorola_e15";
  mode: "cold_local" | "warm_reuse";
  reportPath: string;
  buildPath?: string;
  sessionPath?: string;
  build?: any;
  session?: any;
  report: any;
  samples: Sample[];
  environment: { hardware: string; device_model: string; os_version: string; abi: string; runtime: string; browser: string };
  sessionId: string;
  rawHashes: Record<string, string>;
};

async function nativeEvidence(target: Evidence["target"], mode: Evidence["mode"]): Promise<Evidence> {
  const reportPath = resolve(taceoRoot, "evidence", `oprf_o2__${target === "macbook_m4" ? "mac_native_diagnostic" : "motorola_e15"}__circom_groth16__${mode}.json`);
  const report = await json(reportPath);
  const reportArtifacts = report.artifacts?.hashes ?? {};
  if (reportArtifacts.zkey !== zkeyHash || reportArtifacts.graph !== graphHash || reportArtifacts.input !== inputHash) {
    throw new Error(`${reportPath}: artifact identity does not match the TACEO 0.2.1 campaign assets`);
  }
  const samples = report.samples.map(sampleFromNative);
  if (samples.length !== 6) throw new Error(`${reportPath}: expected six samples`);
  const rawHashes = { report: await sha256(reportPath), ...report.artifacts.hashes };
  return {
    target,
    mode,
    reportPath,
    report,
    samples,
    environment: report.environment,
    sessionId: target === "motorola_e15" ? serial : "",
    rawHashes,
  };
}

async function iphoneEvidence(mode: Evidence["mode"]): Promise<Evidence> {
  const warm = mode === "warm_reuse";
  const buildId = warm ? "69e1acdc072c04776792c4741d202a4ad9f56915" : "2bbd16bc1cbd766f27f67bd3fead1042c93a116d";
  const sessionId = warm ? "5871c1f8443e9d6799c332e8e83d39d5cb0003ef" : "bb74e938435414e7a6de51d8445d92077c8a24f4";
  const rootPath = resolve(taceoRoot, warm ? "browserstack-warm-fetch" : "browserstack-cold-fetch", buildId, `session-${sessionId}`);
  const reportPath = resolve(rootPath, "bench-report.json");
  const buildPath = resolve(taceoRoot, warm ? "browserstack-warm-fetch" : "browserstack-cold-fetch", buildId, "build.json");
  const sessionPath = resolve(rootPath, "session.json");
  const report = await json(reportPath);
  const build = await json(buildPath);
  const session = await json(sessionPath);
  const buildDevices = (Array.isArray(build.devices) ? build.devices : Object.values(build.devices ?? {})) as any[];
  const deviceStatuses = buildDevices.map((item: any) => item.status ?? item.sessions?.[0]?.status);
  const sessionPassed = session.status === "passed"
    || (session.test_status?.SUCCESS === 1
      && session.test_status?.FAILED === 0
      && session.test_status?.TIMEDOUT === 0
      && session.test_status?.ERROR === 0)
    || (session.testcases?.status?.passed === 1
      && session.testcases?.status?.failed === 0
      && session.testcases?.status?.timedout === 0
      && session.testcases?.status?.error === 0);
  const browserStackPassed = (build.status === "done" || build.status === "passed")
    && deviceStatuses.length === 1
    && deviceStatuses[0] === "passed"
    && sessionPassed;
  if (!browserStackPassed) throw new Error(`${reportPath}: BrowserStack run did not pass`);
  const buildDevice = buildDevices[0] ?? {};
  const deviceLabel = String(session.device ?? buildDevice.device ?? Object.keys(build.devices ?? {})[0] ?? "");
  const osMatch = deviceLabel.match(/-(\d+(?:\.\d+)*)$/);
  const deviceModel = String(buildDevice.device ?? (osMatch ? deviceLabel.slice(0, -osMatch[0].length) : deviceLabel));
  const osVersion = String(buildDevice.os_version ?? osMatch?.[1] ?? "");
  if (deviceModel !== "iPhone SE 2022" || !osVersion.startsWith("15.")) throw new Error(`${reportPath}: unexpected device`);
  const reports = Array.isArray(report) ? report : [report];
  for (const item of reports) {
    const metrics = item.custom_metrics?.run_u64 ?? {};
    if (metrics.zkey_size_bytes !== zkeySize || metrics.graph_size_bytes !== graphSize || metrics.input_size_bytes !== inputSize || metrics.proving_payload_size_bytes !== payloadSize) {
      throw new Error(`${reportPath}: BrowserStack report payload does not match the pinned TACEO assets`);
    }
  }
  const samples = mode === "warm_reuse"
    ? customSample(reports[0], 0, true, null) && [0, 1, 2, 3, 4, 5].map((index) => customSample(reports[0], index, index === 0, index === 0 ? null : index - 1))
    : reports.map((item, index) => customSample(item, 0, index === 0, 0));
  if (samples.length !== 6) throw new Error(`${reportPath}: expected six samples`);
  const rawHashes = {
    report: await sha256(reportPath),
    build: await sha256(buildPath),
    session: await sha256(sessionPath),
  };
  return {
    target: "iphone_se_2022",
    mode,
    reportPath,
    buildPath,
    sessionPath,
    build,
    session,
    report,
    samples,
    environment: {
      hardware: "iphone_se_2022",
      device_model: deviceModel,
      os_version: osVersion,
      abi: "arm64",
      runtime: "ios_native",
      browser: "",
    },
    sessionId: `${buildId}/${sessionId}`,
    rawHashes,
  };
}

function note() {
  return "Matched O2 profile: World ID nullifier statement and frozen semantic inputs, including the same public nullifier. Replaced the prior Circom OPRF rows with TACEO circom-helpers main 8aacd73ed6ab0a2b9b2158e613acfa920860865a and circom-witness-rs codex/remove-cxx-bridge-and-grep e11206a9f453145dcd6b814523cbfba4f60cf5c6. Proving payload is zkey + regenerated witness graph + frozen input JSON; mobile IPA/XCUITest upload size is excluded. Valid proof acceptance and tampered-proof rejection were required before timing.";
}

function replaceRows(rows: Row[], evidence: Evidence): Row[] {
  const targetRows = rows.filter((row) => row.circuit === "oprf_nullifier" && row.prover === "circom_groth16" && row.hardware === evidence.target && row.timing_mode === evidence.mode);
  if (targetRows.length !== 6) throw new Error(`${evidence.target}/${evidence.mode}: expected six existing rows, found ${targetRows.length}`);
  const byIndex = new Map(targetRows.map((row) => [Number(row.sample_index), row]));
  return rows.map((row) => {
    if (!(row.circuit === "oprf_nullifier" && row.prover === "circom_groth16" && row.hardware === evidence.target && row.timing_mode === evidence.mode)) return row;
    const index = evidence.samples.findIndex((sample) => sample.warmup ? row.sample_kind === "warmup" : row.sample_kind === "measured" && Number(row.sample_index) === evidence.samples.indexOf(sample));
    const sample = evidence.samples[index < 0 ? Number(row.sample_index) : index];
    if (!sample) throw new Error(`${evidence.target}/${evidence.mode}: row/sample mismatch`);
    const rawEvidence = evidence.rawHashes;
    const artifactHashes = { zkey: zkeyHash, graph: graphHash, input: inputHash, ...rawEvidence };
    const packageVersions = JSON.stringify({
      circom: "2.2.2",
      circom_helpers: helpersCommit,
      circom_witness_rs: witnessCommit,
      taceo_groth16: "0.2.1",
      taceo_groth16_material: "0.4.2",
      witness_graph_patch: "circom-helpers-graph-api.patch",
      android_abi_patch: "as_limbs()[0] as usize",
    });
    const evidencePath = [evidence.reportPath, evidence.buildPath, evidence.sessionPath].filter(Boolean).join(";");
    return {
      ...row,
      campaign_id: campaignId,
      attempt_id: `${row.circuit}__${evidence.target}__circom_groth16__${evidence.mode}-${sample.warmup ? 0 : Number(row.sample_index)}`,
      recorded_at_utc: evidence.report.created_at_utc ?? evidence.session?.start_time ?? evidence.build?.start_time ?? row.recorded_at_utc,
      device_model: evidence.environment.device_model,
      os_version: evidence.environment.os_version,
      abi: evidence.environment.abi,
      runtime: evidence.environment.runtime,
      browser: evidence.environment.browser,
      prover_backend: "taceo-groth16-0.2.1",
      witness_backend: "circom-witness-rs@0.3.0 (codex/remove-cxx-bridge-and-grep)",
      sample_kind: sample.warmup ? "warmup" : "measured",
      sample_index: sample.warmup ? "0" : String(evidence.samples.filter((item) => !item.warmup).indexOf(sample) + 1),
      status: "ok",
      initialization_time_ms: String(sample.initialization),
      witness_time_ms: String(sample.witness),
      prover_time_ms: String(sample.prove),
      verify_time_ms: String(sample.verify),
      total_time_ms: String(sample.total),
      peak_memory_mib: sample.peak == null ? "" : String(sample.peak),
      proof_size_bytes: String(sample.proof),
      circuit_size_bytes: String(payloadSize),
      artifact_size_bytes: String(artifactSize),
      bundle_size_bytes: String(payloadSize),
      artifact_version: "input-to-proof-v1-taceo-groth16-0.2.1",
      source_commit: circuitCommit,
      package_versions: packageVersions,
      artifact_hashes: JSON.stringify(artifactHashes),
      session_id: evidence.sessionId,
      non_equivalence_note: note(),
      failure_code: "",
      failure_detail: "",
      evidence_path: evidencePath,
      input_to_proof_time_ms: String(sample.total),
    };
  });
}

const parsed = parseCsv(await Bun.file(csvPath).text());
const requiredColumns = ["circuit", "prover", "hardware", "timing_mode", "sample_kind", "sample_index"];
for (const column of requiredColumns) if (!parsed.columns.includes(column)) throw new Error(`CSV missing ${column}`);
const evidence = [
  await nativeEvidence("macbook_m4", "cold_local"),
  await nativeEvidence("macbook_m4", "warm_reuse"),
  await nativeEvidence("motorola_e15", "cold_local"),
  await nativeEvidence("motorola_e15", "warm_reuse"),
  await iphoneEvidence("cold_local"),
  await iphoneEvidence("warm_reuse"),
];
let rows = parsed.rows;
for (const item of evidence) rows = replaceRows(rows, item);

const expected = new Set(evidence.map((item) => `${item.target}|${item.mode}`));
for (const item of expected) {
  const [target, mode] = item.split("|");
  const count = rows.filter((row) => row.circuit === "oprf_nullifier" && row.prover === "circom_groth16" && row.hardware === target && row.timing_mode === mode).length;
  if (count !== 6) throw new Error(`${item}: expected six rows after replacement, found ${count}`);
}
const output = [parsed.columns.join(","), ...rows.map((row) => parsed.columns.map((column) => csvValue(row[column] ?? "")).join(","))].join("\n") + "\n";
await Bun.write(csvPath, output);
console.log(`${csvPath}: replaced ${evidence.length} TACEO OPRF series; preserved ${rows.length} rows and ${parsed.columns.length} columns`);
