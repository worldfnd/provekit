#!/usr/bin/env bun

import {
  CIRCUITS,
  CSV_COLUMNS,
  EXPECTED_CELL_COUNT,
  EXPECTED_MEASURED_PER_OK_CELL,
  EXPECTED_RUNTIME,
  EXPECTED_WARMUPS_PER_OK_CELL,
  HARDWARE,
  PROVERS,
  SAMPLE_KINDS,
  STATUSES,
  cellKey,
  expectedCellKeys,
  variantKey,
  type AttemptRecord,
  type CsvColumn,
  type Status,
} from "./schema";

const METRIC_COLUMNS = [
  "initialization_time_ms",
  "witness_time_ms",
  "prover_time_ms",
  "verify_time_ms",
  "total_time_ms",
  "peak_memory_mib",
  "proof_size_bytes",
  "circuit_size_bytes",
  "artifact_size_bytes",
  "bundle_size_bytes",
  "constraint_count",
] as const satisfies readonly CsvColumn[];

const GAP_STATUSES: ReadonlySet<Status> = new Set(
  STATUSES.filter((status) => status !== "ok"),
);
const enumValues = {
  hardware: new Set<string>(HARDWARE),
  runtime: new Set<string>(Object.values(EXPECTED_RUNTIME)),
  circuit: new Set<string>(CIRCUITS),
  prover: new Set<string>(PROVERS),
  sample_kind: new Set<string>(SAMPLE_KINDS),
  status: new Set<string>(STATUSES),
};

export class ValidationError extends Error {
  constructor(public readonly issues: string[]) {
    super(issues.join("\n"));
    this.name = "ValidationError";
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredString(record: Record<string, unknown>, field: CsvColumn, issues: string[]) {
  const value = record[field];
  if (typeof value !== "string" || value.trim() === "") {
    issues.push(`${field} must be a non-empty string`);
    return "";
  }
  return value;
}

function optionalString(record: Record<string, unknown>, field: CsvColumn, issues: string[]) {
  const value = record[field];
  if (typeof value !== "string") {
    issues.push(`${field} must be a string (use an empty string when not applicable)`);
    return "";
  }
  return value;
}

function nullableNumber(record: Record<string, unknown>, field: CsvColumn, issues: string[]) {
  const value = record[field];
  if (value === null) return null;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    issues.push(`${field} must be null or a finite non-negative number`);
    return null;
  }
  return value;
}

function parseAttempt(value: unknown, position: number): AttemptRecord {
  const issues: string[] = [];
  if (!isObject(value)) throw new ValidationError([`record ${position} must be an object`]);
  const record = value;

  for (const key of Object.keys(record)) {
    if (!CSV_COLUMNS.includes(key as CsvColumn)) issues.push(`unknown field: ${key}`);
  }
  for (const field of CSV_COLUMNS) {
    if (!(field in record)) issues.push(`missing field: ${field}`);
  }

  const parsed = {
    campaign_id: requiredString(record, "campaign_id", issues),
    attempt_id: requiredString(record, "attempt_id", issues),
    recorded_at_utc: requiredString(record, "recorded_at_utc", issues),
    hardware: requiredString(record, "hardware", issues),
    device_model: requiredString(record, "device_model", issues),
    os_version: requiredString(record, "os_version", issues),
    abi: requiredString(record, "abi", issues),
    runtime: requiredString(record, "runtime", issues),
    browser: optionalString(record, "browser", issues),
    circuit: requiredString(record, "circuit", issues),
    circuit_variant: requiredString(record, "circuit_variant", issues),
    circuit_commit: requiredString(record, "circuit_commit", issues),
    prover: requiredString(record, "prover", issues),
    frontend: requiredString(record, "frontend", issues),
    prover_backend: requiredString(record, "prover_backend", issues),
    witness_backend: optionalString(record, "witness_backend", issues),
    sample_kind: requiredString(record, "sample_kind", issues),
    sample_index: record.sample_index,
    status: requiredString(record, "status", issues),
    initialization_time_ms: nullableNumber(record, "initialization_time_ms", issues),
    witness_time_ms: nullableNumber(record, "witness_time_ms", issues),
    prover_time_ms: nullableNumber(record, "prover_time_ms", issues),
    verify_time_ms: nullableNumber(record, "verify_time_ms", issues),
    total_time_ms: nullableNumber(record, "total_time_ms", issues),
    peak_memory_mib: nullableNumber(record, "peak_memory_mib", issues),
    proof_size_bytes: nullableNumber(record, "proof_size_bytes", issues),
    circuit_size_bytes: nullableNumber(record, "circuit_size_bytes", issues),
    artifact_size_bytes: nullableNumber(record, "artifact_size_bytes", issues),
    bundle_size_bytes: nullableNumber(record, "bundle_size_bytes", issues),
    constraint_count: nullableNumber(record, "constraint_count", issues),
    artifact_version: requiredString(record, "artifact_version", issues),
    source_commit: requiredString(record, "source_commit", issues),
    package_versions: requiredString(record, "package_versions", issues),
    artifact_hashes: requiredString(record, "artifact_hashes", issues),
    session_id: optionalString(record, "session_id", issues),
    non_equivalence_note: requiredString(record, "non_equivalence_note", issues),
    failure_code: optionalString(record, "failure_code", issues),
    failure_detail: optionalString(record, "failure_detail", issues),
    evidence_path: requiredString(record, "evidence_path", issues),
  };

  for (const [field, allowed] of Object.entries(enumValues)) {
    const value = parsed[field as keyof typeof parsed];
    if (typeof value === "string" && !allowed.has(value)) {
      issues.push(`${field} has unsupported value: ${value}`);
    }
  }

  const timestamp = Date.parse(parsed.recorded_at_utc);
  if (!Number.isFinite(timestamp) || !parsed.recorded_at_utc.endsWith("Z")) {
    issues.push("recorded_at_utc must be an ISO-8601 UTC timestamp ending in Z");
  }
  if (
    parsed.hardware in EXPECTED_RUNTIME &&
    EXPECTED_RUNTIME[parsed.hardware as keyof typeof EXPECTED_RUNTIME] !== parsed.runtime
  ) {
    issues.push(
      `runtime ${parsed.runtime} does not match ${parsed.hardware}; expected ${
        EXPECTED_RUNTIME[parsed.hardware as keyof typeof EXPECTED_RUNTIME]
      }`,
    );
  }
  if (parsed.runtime === "browser_wasm" && parsed.browser === "") {
    issues.push("browser_wasm records require browser");
  }
  if (parsed.runtime !== "browser_wasm" && parsed.browser !== "") {
    issues.push("native records must leave browser blank");
  }
  const expectedFrontend =
    parsed.prover === "circom_groth16" ? "circom" : parsed.prover ? "noir" : "";
  if (expectedFrontend && parsed.frontend !== expectedFrontend) {
    issues.push(`${parsed.prover} records require frontend=${expectedFrontend}`);
  }

  const isGap = GAP_STATUSES.has(parsed.status as (typeof STATUSES)[number]);
  if (parsed.status === "ok") {
    if (parsed.sample_kind === "gap") issues.push("ok records cannot use sample_kind=gap");
    if (!Number.isInteger(parsed.sample_index) || (parsed.sample_index as number) < 0) {
      issues.push("ok records require a non-negative integer sample_index");
    }
    if (
      parsed.sample_kind === "measured" &&
      (parsed.prover_time_ms === null || parsed.total_time_ms === null)
    ) {
      issues.push("ok measured records require prover_time_ms and total_time_ms");
    }
    if (
      parsed.sample_kind === "measured" &&
      (parsed.artifact_size_bytes === null ||
        parsed.proof_size_bytes === null ||
        parsed.peak_memory_mib === null)
    ) {
      issues.push(
        "ok measured records require proving payload size, proof size, and peak process memory",
      );
    }
    if (
      parsed.sample_kind === "warmup" &&
      ((parsed.prover_time_ms === null) !== (parsed.total_time_ms === null))
    ) {
      issues.push(
        "ok warmup records must provide both prover_time_ms and total_time_ms or leave both blank",
      );
    }
    if (parsed.failure_code !== "" || parsed.failure_detail !== "") {
      issues.push("ok records must leave failure_code and failure_detail blank");
    }
  } else if (isGap) {
    if (parsed.sample_kind !== "gap") issues.push(`${parsed.status} records require sample_kind=gap`);
    if (parsed.sample_index !== null) issues.push("gap records require sample_index=null");
    for (const metric of METRIC_COLUMNS) {
      if (parsed[metric] !== null) issues.push(`gap records require ${metric}=null`);
    }
    if (parsed.failure_code === "" || parsed.failure_detail === "") {
      issues.push("gap records require failure_code and failure_detail");
    }
  }

  if (parsed.prover === "circom_groth16" && parsed.witness_backend === "") {
    issues.push("circom_groth16 records require witness_backend");
  }
  if (parsed.prover !== "circom_groth16" && parsed.witness_time_ms !== null) {
    issues.push("witness_time_ms is reserved for separately measured Circom witness generation");
  }
  if (
    parsed.witness_time_ms !== null &&
    parsed.total_time_ms !== null &&
    parsed.prover_time_ms !== null &&
    parsed.total_time_ms + Number.EPSILON < parsed.witness_time_ms + parsed.prover_time_ms
  ) {
    issues.push("total_time_ms cannot be less than witness_time_ms + prover_time_ms");
  }
  if (parsed.proof_size_bytes !== null && !Number.isInteger(parsed.proof_size_bytes)) {
    issues.push("proof_size_bytes must be an integer number of bytes");
  }
  for (const field of [
    "circuit_size_bytes",
    "artifact_size_bytes",
    "bundle_size_bytes",
    "constraint_count",
  ] as const) {
    if (parsed[field] !== null && !Number.isInteger(parsed[field])) {
      issues.push(`${field} must be an integer`);
    }
  }

  if (issues.length) {
    throw new ValidationError(issues.map((issue) => `record ${position} (${parsed.attempt_id}): ${issue}`));
  }
  return parsed as AttemptRecord;
}

export function validateAttempts(input: unknown, requireCompleteMatrix = true): AttemptRecord[] {
  if (!Array.isArray(input)) throw new ValidationError(["input must be a JSON array of attempt records"]);

  const records: AttemptRecord[] = [];
  const issues: string[] = [];
  input.forEach((value, index) => {
    try {
      records.push(parseAttempt(value, index));
    } catch (error) {
      if (error instanceof ValidationError) issues.push(...error.issues);
      else throw error;
    }
  });

  const attemptIds = new Set<string>();
  const sampleKeys = new Set<string>();
  for (const record of records) {
    if (attemptIds.has(record.attempt_id)) issues.push(`duplicate attempt_id: ${record.attempt_id}`);
    attemptIds.add(record.attempt_id);
    const sampleKey =
      `${variantKey(record)}|${record.sample_kind}|${record.sample_index ?? "gap"}`;
    if (sampleKeys.has(sampleKey)) issues.push(`duplicate cell sample: ${sampleKey}`);
    sampleKeys.add(sampleKey);
  }

  const byCell = Map.groupBy(records, cellKey);
  if (requireCompleteMatrix) {
    for (const key of expectedCellKeys()) {
      const cell = byCell.get(key) ?? [];
      if (cell.length === 0) {
        issues.push(`missing expected cell: ${key}`);
        continue;
      }
      const ok = cell.filter((record) => record.status === "ok");
      const gaps = cell.filter((record) => record.status !== "ok");
      if (ok.length > 0 && gaps.length > 0) issues.push(`cell mixes ok and gap records: ${key}`);
      if (gaps.length > 1) issues.push(`gap cell must have exactly one record: ${key}`);
      if (ok.length > 0) {
        const byVariant = Map.groupBy(ok, (record) => record.circuit_variant);
        for (const [variant, variantRecords] of byVariant) {
          const variantLabel = `${key}|${variant}`;
          const warmups = variantRecords.filter((record) => record.sample_kind === "warmup");
          const measured = variantRecords.filter((record) => record.sample_kind === "measured");
          if (warmups.length !== EXPECTED_WARMUPS_PER_OK_CELL) {
            issues.push(`ok variant requires 1 warmup, found ${warmups.length}: ${variantLabel}`);
          }
          if (measured.length !== EXPECTED_MEASURED_PER_OK_CELL) {
            issues.push(
              `ok variant requires 5 measured samples, found ${measured.length}: ${variantLabel}`,
            );
          }
          if (warmups[0]?.sample_index !== 0) {
            issues.push(`warmup sample_index must be 0: ${variantLabel}`);
          }
          const indexes = measured.map((record) => record.sample_index).sort();
          if (JSON.stringify(indexes) !== JSON.stringify([1, 2, 3, 4, 5])) {
            issues.push(`measured sample_index values must be 1..5: ${variantLabel}`);
          }
        }
      }
    }
    if (byCell.size !== EXPECTED_CELL_COUNT) {
      issues.push(`expected ${EXPECTED_CELL_COUNT} unique cells, found ${byCell.size}`);
    }
  }

  const campaignIds = new Set(records.map((record) => record.campaign_id));
  if (campaignIds.size > 1) issues.push("input contains more than one campaign_id");

  if (issues.length) throw new ValidationError(issues);
  return records.sort((a, b) =>
    [
      a.hardware,
      a.circuit,
      a.prover,
      a.circuit_variant,
      a.sample_kind,
      a.sample_index ?? -1,
      a.attempt_id,
    ]
      .join("|")
      .localeCompare(
        [
          b.hardware,
          b.circuit,
          b.prover,
          b.circuit_variant,
          b.sample_kind,
          b.sample_index ?? -1,
          b.attempt_id,
        ].join("|"),
      ),
  );
}

function csvValue(value: unknown): string {
  if (value === null || value === undefined) return "";
  const text = String(value);
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

export function toCsv(records: AttemptRecord[]): string {
  const lines = [
    CSV_COLUMNS.join(","),
    ...records.map((record) => CSV_COLUMNS.map((column) => csvValue(record[column])).join(",")),
  ];
  return `${lines.join("\n")}\n`;
}

function usage(): never {
  console.error(
    "usage: bun export-benchmark-csv.ts <attempts.json> <samples.csv> [--allow-partial]",
  );
  process.exit(2);
}

if (import.meta.main) {
  const [inputPath, outputPath, flag] = process.argv.slice(2);
  if (!inputPath || !outputPath || (flag !== undefined && flag !== "--allow-partial")) usage();
  try {
    const input = await Bun.file(inputPath).json();
    const records = validateAttempts(input, flag !== "--allow-partial");
    await Bun.write(outputPath, toCsv(records));
    console.log(`wrote ${records.length} sample records to ${outputPath}`);
  } catch (error) {
    if (error instanceof ValidationError) {
      for (const issue of error.issues) console.error(`error: ${issue}`);
      process.exit(1);
    }
    throw error;
  }
}
