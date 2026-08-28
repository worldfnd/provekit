export const CSV_COLUMNS = [
  "campaign_id",
  "attempt_id",
  "recorded_at_utc",
  "hardware",
  "device_model",
  "os_version",
  "abi",
  "runtime",
  "browser",
  "circuit",
  "circuit_variant",
  "circuit_commit",
  "prover",
  "frontend",
  "prover_backend",
  "witness_backend",
  "sample_kind",
  "sample_index",
  "status",
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
  "artifact_version",
  "source_commit",
  "package_versions",
  "artifact_hashes",
  "session_id",
  "non_equivalence_note",
  "failure_code",
  "failure_detail",
  "evidence_path",
] as const;

export type CsvColumn = (typeof CSV_COLUMNS)[number];

export const HARDWARE = ["iphone_se_2022", "motorola_e15", "macbook_m4"] as const;
export const RUNTIMES = ["ios_native", "android_native", "browser_wasm"] as const;
export const CIRCUITS = ["oprf", "passport", "webauthn"] as const;
export const PROVERS = [
  "provekit_v1",
  "noir_barretenberg",
  "circom_groth16",
] as const;
export const SAMPLE_KINDS = ["warmup", "measured", "gap"] as const;
export const STATUSES = [
  "ok",
  "unsupported",
  "build_failed",
  "crashed",
  "runtime_failed",
  "timed_out",
  "zero_samples",
  "not_run",
] as const;

export type Hardware = (typeof HARDWARE)[number];
export type Runtime = (typeof RUNTIMES)[number];
export type Circuit = (typeof CIRCUITS)[number];
export type Prover = (typeof PROVERS)[number];
export type SampleKind = (typeof SAMPLE_KINDS)[number];
export type Status = (typeof STATUSES)[number];

export interface AttemptRecord {
  campaign_id: string;
  attempt_id: string;
  recorded_at_utc: string;
  hardware: Hardware;
  device_model: string;
  os_version: string;
  abi: string;
  runtime: Runtime;
  browser: string;
  circuit: Circuit;
  circuit_variant: string;
  circuit_commit: string;
  prover: Prover;
  frontend: string;
  prover_backend: string;
  witness_backend: string;
  sample_kind: SampleKind;
  sample_index: number | null;
  status: Status;
  initialization_time_ms: number | null;
  witness_time_ms: number | null;
  prover_time_ms: number | null;
  verify_time_ms: number | null;
  total_time_ms: number | null;
  peak_memory_mib: number | null;
  proof_size_bytes: number | null;
  circuit_size_bytes: number | null;
  artifact_size_bytes: number | null;
  bundle_size_bytes: number | null;
  constraint_count: number | null;
  artifact_version: string;
  source_commit: string;
  package_versions: string;
  artifact_hashes: string;
  session_id: string;
  non_equivalence_note: string;
  failure_code: string;
  failure_detail: string;
  evidence_path: string;
}

export const EXPECTED_RUNTIME: Record<Hardware, Runtime> = {
  iphone_se_2022: "ios_native",
  motorola_e15: "android_native",
  macbook_m4: "browser_wasm",
};

export const EXPECTED_CELL_COUNT = HARDWARE.length * CIRCUITS.length * PROVERS.length;
export const EXPECTED_WARMUPS_PER_OK_CELL = 1;
export const EXPECTED_MEASURED_PER_OK_CELL = 5;

export function cellKey(record: Pick<AttemptRecord, "hardware" | "circuit" | "prover">) {
  return `${record.hardware}|${record.circuit}|${record.prover}`;
}

export function variantKey(
  record: Pick<AttemptRecord, "hardware" | "circuit" | "circuit_variant" | "prover">,
) {
  return `${cellKey(record)}|${record.circuit_variant}`;
}

export function expectedCellKeys(): string[] {
  return HARDWARE.flatMap((hardware) =>
    CIRCUITS.flatMap((circuit) =>
      PROVERS.map((prover) => `${hardware}|${circuit}|${prover}`),
    ),
  );
}
