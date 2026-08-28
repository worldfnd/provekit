import { createHash } from "node:crypto";
import { basename, resolve } from "node:path";
import { CSV_COLUMNS, expectedSeries, seriesId, type Profile, type Target, type TimingMode } from "../../input-to-proof-data/schema";
import config from "./config.json";

type Cell = string | number | boolean | null;
type Row = Record<(typeof CSV_COLUMNS)[number], Cell>;
type SuccessSample = {
  sample_index: number;
  warmup: boolean;
  status: "ok";
  initialization_time_ms: number | null;
  witness_time_ms: number | null;
  prover_time_ms: number | null;
  verify_time_ms: number | null;
  total_time_ms: number;
  input_to_proof_time_ms: number;
  peak_memory_mib: number | null;
  proof_size_bytes: number;
  valid_proof_accepted: true;
  tampered_proof_rejected: true;
};
type Evidence = {
  schema_version: typeof config.schema_version;
  series_id: string;
  profile: Profile;
  target: Extract<Target, "iphone_se_2022" | "motorola_e15">;
  timing_mode: TimingMode;
  created_at_utc: string;
  environment: {
    hardware: "iphone_se_2022" | "motorola_e15";
    device_model: string;
    os_version: string;
    abi: string;
    runtime: "ios_native" | "android_native";
    browser: "";
    session_id: string;
  };
  circuit: { name: string; variant: string; commit: string; constraint_count: number | null };
  backend: {
    frontend: "circom";
    prover_backend: typeof config.prover_backend;
    witness_backend: typeof config.witness_backend;
    source_commit: typeof config.circom_helpers_commit;
    package_versions: typeof config.package_versions;
  };
  artifacts: {
    proving_payload_size_bytes: number;
    artifact_size_bytes: number;
    bundle_size_bytes: number;
    hashes: Record<string, string>;
  };
  public_outputs_sha256: string;
  status: "ok" | "runtime_failed" | "build_failed" | "crashed" | "timed_out" | "unsupported";
  failure_code: string;
  failure_detail: string;
  samples: SuccessSample[];
};

const here = import.meta.dir;
const baselineDefault = resolve(here, "../../input-to-proof-data/input-to-proof-samples.csv");
const evidenceDefault = resolve(here, "evidence");
const outputDefault = resolve(here, "input-to-proof-samples.taceo-candidate.csv");
const nativeTargets = ["iphone_se_2022", "motorola_e15"] as const;
const profiles = ["passport_complete_age_check", "passport_p1", "oprf_o2", "webauthn_closest_analogue"] as const;
const modes = ["cold_local", "warm_reuse"] as const;
const replacementSeries = profiles.flatMap((profile) => nativeTargets.flatMap((target) => modes.map((mode) => seriesId(profile, target, "circom_groth16", mode))));

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [], value = "", quoted = false;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (char === '"' && text[i + 1] === '"') { value += '"'; i++; }
      else if (char === '"') quoted = false;
      else value += char;
    } else if (char === '"') quoted = true;
    else if (char === ",") { row.push(value); value = ""; }
    else if (char === "\n") { row.push(value); rows.push(row); row = []; value = ""; }
    else if (char !== "\r") value += char;
  }
  assert(!quoted, "baseline CSV has an unterminated quoted field");
  if (value.length || row.length) { row.push(value); rows.push(row); }
  return rows;
}

function readRows(text: string): Row[] {
  const parsed = parseCsv(text);
  const header = parsed.shift();
  assert(header?.join("\0") === CSV_COLUMNS.join("\0"), "baseline schema/order differs from input-to-proof-samples.csv");
  return parsed.filter((values) => values.length > 1).map((values, rowIndex) => {
    assert(values.length === CSV_COLUMNS.length, `baseline row ${rowIndex + 2} has ${values.length} fields, expected ${CSV_COLUMNS.length}`);
    return Object.fromEntries(CSV_COLUMNS.map((column, index) => [column, values[index]])) as Row;
  });
}

function csvValue(value: Cell) {
  if (value == null) return "";
  const text = String(value);
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function writeRows(rows: Row[]) {
  return [CSV_COLUMNS.join(","), ...rows.map((row) => CSV_COLUMNS.map((column) => csvValue(row[column])).join(","))].join("\n") + "\n";
}

function sha256(bytes: Uint8Array) {
  return createHash("sha256").update(bytes).digest("hex");
}

function isHash(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function profileFor(row: Row): Profile {
  if (row.circuit === "passport_complete_age_check") return "passport_complete_age_check";
  if (row.circuit === "passport_age_integrity") return "passport_p1";
  if (row.circuit === "oprf_nullifier") return "oprf_o2";
  if (row.circuit === "webauthn") return "webauthn_closest_analogue";
  throw new Error(`unknown circuit in CSV: ${row.circuit}`);
}

function targetFor(row: Row): Target {
  if (row.hardware === "macbook_m4") return "mac_chrome";
  if (row.hardware === "iphone_se_2022") return "iphone_se_2022";
  if (row.hardware === "motorola_e15") return "motorola_e15";
  throw new Error(`unknown hardware in CSV: ${row.hardware}`);
}

function rowSeries(row: Row) {
  return seriesId(profileFor(row), targetFor(row), row.prover as any, row.timing_mode as TimingMode);
}

function validateEvidence(e: Evidence, expectedId: string, path: string) {
  assert(e.schema_version === config.schema_version, `${path}: schema_version is not pinned ${config.schema_version}`);
  assert(e.series_id === expectedId, `${path}: series_id mismatch`);
  assert(e.series_id === seriesId(e.profile, e.target, "circom_groth16", e.timing_mode), `${path}: identity fields disagree with series_id`);
  assert(e.environment.hardware === e.target, `${path}: environment hardware/target mismatch`);
  assert((e.target === "iphone_se_2022" && e.environment.runtime === "ios_native") || (e.target === "motorola_e15" && e.environment.runtime === "android_native"), `${path}: invalid native runtime`);
  assert(e.environment.browser === "", `${path}: native evidence cannot name a browser`);
  assert(e.backend.frontend === "circom", `${path}: frontend must be circom`);
  assert(e.backend.prover_backend === config.prover_backend, `${path}: prover backend is not pinned ${config.prover_backend}`);
  assert(e.backend.witness_backend === config.witness_backend, `${path}: witness backend is not pinned ${config.witness_backend}`);
  assert(e.backend.source_commit === config.circom_helpers_commit, `${path}: circom-helpers commit drift`);
  assert(JSON.stringify(e.backend.package_versions) === JSON.stringify(config.package_versions), `${path}: package version drift`);
  assert(Object.keys(e.artifacts.hashes).length >= 2, `${path}: at least two proving artifact hashes are required`);
  for (const [name, hash] of Object.entries(e.artifacts.hashes)) assert(isHash(hash), `${path}: invalid ${name} SHA-256`);
  if (e.status === "ok") {
    assert(isHash(e.public_outputs_sha256), `${path}: successful evidence requires a lowercase public_outputs_sha256`);
    assert(!e.failure_code && !e.failure_detail, `${path}: successful evidence cannot contain failure fields`);
    assert(e.artifacts.proving_payload_size_bytes > 0 && e.artifacts.artifact_size_bytes > 0 && e.artifacts.bundle_size_bytes > 0, `${path}: artifact sizes must be positive exact values`);
    assert(e.samples.length === 6, `${path}: successful series requires one warmup and five measured samples`);
    e.samples.forEach((sample, index) => {
      assert(sample.status === "ok" && sample.sample_index === index && sample.warmup === (index === 0), `${path}: samples must be ordered warmup 0 then measured 1..5`);
      for (const key of ["total_time_ms", "input_to_proof_time_ms", "proof_size_bytes"] as const) assert(typeof sample[key] === "number" && sample[key]! > 0, `${path}: sample ${index} has invalid ${key}`);
      assert((sample.witness_time_ms == null && sample.prover_time_ms == null) ||
        (typeof sample.witness_time_ms === "number" && sample.witness_time_ms > 0 && typeof sample.prover_time_ms === "number" && sample.prover_time_ms > 0),
      `${path}: sample ${index} must provide both component timings or neither when only coupled input-to-proof was instrumented`);
      assert(sample.valid_proof_accepted && sample.tampered_proof_rejected, `${path}: sample ${index} failed correctness gate`);
      if (index > 0) assert(typeof sample.peak_memory_mib === "number" && sample.peak_memory_mib > 0, `${path}: measured sample ${index} lacks peak RSS`);
    });
  } else {
    assert(e.public_outputs_sha256 === "" || isHash(e.public_outputs_sha256), `${path}: failed evidence public_outputs_sha256 must be empty or lowercase SHA-256`);
    assert(e.samples.length === 0, `${path}: failed series must not contain samples`);
    assert(Boolean(e.failure_code && e.failure_detail), `${path}: failed series requires structured failure evidence`);
  }
}

function makeRows(e: Evidence, evidencePath: string, evidenceHash: string): Row[] {
  const common: Partial<Row> = {
    campaign_id: config.candidate_campaign_id, recorded_at_utc: e.created_at_utc,
    hardware: e.environment.hardware, device_model: e.environment.device_model, os_version: e.environment.os_version,
    abi: e.environment.abi, runtime: e.environment.runtime, browser: "", circuit: e.circuit.name,
    circuit_variant: e.circuit.variant, circuit_commit: e.circuit.commit, prover: "circom_groth16", frontend: "circom",
    prover_backend: e.backend.prover_backend, witness_backend: e.backend.witness_backend,
    constraint_count: e.circuit.constraint_count, artifact_version: config.schema_version,
    source_commit: e.backend.source_commit, package_versions: JSON.stringify(e.backend.package_versions),
    artifact_hashes: JSON.stringify({ ...e.artifacts.hashes, raw_evidence_sha256: evidenceHash, public_outputs_sha256: e.public_outputs_sha256 }),
    session_id: e.environment.session_id,
    non_equivalence_note: e.profile === "oprf_o2"
      ? "TACEO updated-production OPRF query+nullifier. Public outputs match, but optimized witness graphs and matching Ark zkeys differ from the frozen Rapidsnark material; this is not a backend-only strict-parity comparison."
      : "TACEO native Circom compatibility gap; no Rapidsnark timing was substituted.",
    evidence_path: evidencePath, timing_mode: e.timing_mode,
  };
  if (e.status !== "ok") return [{
    ...Object.fromEntries(CSV_COLUMNS.map((column) => [column, null])), ...common,
    attempt_id: `${e.series_id}-gap`, sample_kind: "gap", status: e.status,
    failure_code: e.failure_code, failure_detail: e.failure_detail,
  } as Row];
  return e.samples.map((sample) => ({
    ...Object.fromEntries(CSV_COLUMNS.map((column) => [column, null])), ...common,
    attempt_id: `${e.series_id}-${sample.sample_index}`, sample_kind: sample.warmup ? "warmup" : "measured",
    sample_index: sample.warmup ? 0 : sample.sample_index, status: "ok",
    initialization_time_ms: sample.initialization_time_ms, witness_time_ms: sample.witness_time_ms,
    prover_time_ms: sample.prover_time_ms, verify_time_ms: sample.verify_time_ms, total_time_ms: sample.total_time_ms,
    input_to_proof_time_ms: sample.input_to_proof_time_ms, peak_memory_mib: sample.peak_memory_mib,
    proof_size_bytes: sample.proof_size_bytes, circuit_size_bytes: e.artifacts.proving_payload_size_bytes,
    artifact_size_bytes: e.artifacts.artifact_size_bytes, bundle_size_bytes: e.artifacts.bundle_size_bytes,
    failure_code: "", failure_detail: "",
  } as Row));
}

export function validateCandidate(baseline: Row[], candidate: Row[]) {
  const expected = new Set(expectedSeries());
  const grouped = new Map<string, Row[]>();
  for (const row of candidate) {
    const id = rowSeries(row);
    assert(expected.has(id), `candidate contains unexpected series ${id}`);
    grouped.set(id, [...(grouped.get(id) ?? []), row]);
  }
  assert(grouped.size === 72, `candidate has ${grouped.size}/72 logical series`);
  for (const id of expected) {
    const rows = grouped.get(id)!;
    if (rows.length === 1 && rows[0].sample_kind === "gap") {
      for (const metric of ["witness_time_ms", "prover_time_ms", "input_to_proof_time_ms", "peak_memory_mib", "proof_size_bytes", "circuit_size_bytes"] as const) assert(rows[0][metric] == null, `${id}: gap metric ${metric} must be blank`);
      continue;
    }
    assert(rows.length === 6, `${id}: requires 6 successful rows or one explicit gap, found ${rows.length}`);
    assert(rows.every((row) => row.status === "ok"), `${id}: successful series contains non-ok row`);
  }
  const replace = new Set(replacementSeries);
  const baselineKept = baseline.filter((row) => !replace.has(rowSeries(row)));
  const candidateKept = candidate.filter((row) => !replace.has(rowSeries(row)));
  assert(JSON.stringify(candidateKept) === JSON.stringify(baselineKept), "candidate changed rows outside native Circom replacement scope");
  for (const id of replacementSeries) {
    const rows = grouped.get(id)!;
    assert(rows.every((row) => row.prover_backend === config.prover_backend && row.witness_backend === config.witness_backend), `${id}: retained a non-TACEO native Circom row`);
  }
}

export async function buildCandidate(options: { baselinePath?: string; evidenceDir?: string; outputPath?: string; write?: boolean } = {}) {
  const baselinePath = resolve(options.baselinePath ?? baselineDefault);
  const evidenceDir = resolve(options.evidenceDir ?? evidenceDefault);
  const outputPath = resolve(options.outputPath ?? outputDefault);
  const baseline = readRows(await Bun.file(baselinePath).text());
  const replacements: Row[] = [];
  for (const id of replacementSeries) {
    const path = resolve(evidenceDir, `${id}.json`);
    assert(await Bun.file(path).exists(), `missing TACEO evidence: ${path}`);
    const bytes = new Uint8Array(await Bun.file(path).arrayBuffer());
    let evidence: Evidence;
    try { evidence = JSON.parse(new TextDecoder().decode(bytes)); }
    catch (error) { throw new Error(`${path}: invalid JSON: ${error}`); }
    validateEvidence(evidence, id, path);
    replacements.push(...makeRows(evidence, path, sha256(bytes)));
  }
  const replace = new Set(replacementSeries);
  const candidate = [...baseline.filter((row) => !replace.has(rowSeries(row))), ...replacements];
  validateCandidate(baseline, candidate);
  if (options.write !== false) await Bun.write(outputPath, writeRows(candidate));
  return { rows: candidate, outputPath, replacementSeries: [...replacementSeries] };
}

export { replacementSeries };

if (import.meta.main) {
  const result = await buildCandidate({
    baselinePath: process.env.TACEO_BASELINE_CSV,
    evidenceDir: process.env.TACEO_EVIDENCE_DIR,
    outputPath: process.env.TACEO_CANDIDATE_CSV,
  });
  console.log(`${result.outputPath}: ${result.rows.length} rows, 72 series, ${result.replacementSeries.length} native Circom series replaced`);
}
