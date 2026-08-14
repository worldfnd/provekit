export const CAMPAIGN_ID = "semantic-parity-v1-20260731";

export const PROFILES = ["passport_p1", "oprf_o2", "webauthn_closest_analogue"] as const;
export const TARGETS = ["mac_chrome", "iphone_se_2022", "motorola_e15"] as const;
export const STACKS = ["provekit_v1", "noir_barretenberg", "circom_groth16"] as const;
export const RUNTIMES = ["browser_wasm", "ios_native", "android_native"] as const;
export const STATUSES = ["ok", "unsupported", "build_failed", "crashed", "runtime_failed", "timed_out", "zero_samples", "not_run"] as const;

export type Profile = (typeof PROFILES)[number];
export type Target = (typeof TARGETS)[number];
export type Stack = (typeof STACKS)[number];
export type Runtime = (typeof RUNTIMES)[number];
export type Status = (typeof STATUSES)[number];

export const EXPECTED_RUNTIME: Record<Target, Runtime> = {
  mac_chrome: "browser_wasm",
  iphone_se_2022: "ios_native",
  motorola_e15: "android_native",
};

export const CSV_COLUMNS = [
  "campaign_id", "attempt_id", "recorded_at_utc", "hardware", "device_model", "os_version", "abi",
  "runtime", "browser", "circuit", "circuit_variant", "circuit_commit", "prover", "frontend",
  "prover_backend", "witness_backend", "sample_kind", "sample_index", "status",
  "initialization_time_ms", "witness_time_ms", "prover_time_ms", "verify_time_ms", "total_time_ms",
  "peak_memory_mib", "proof_size_bytes", "circuit_size_bytes", "artifact_size_bytes",
  "bundle_size_bytes", "constraint_count", "artifact_version", "source_commit", "package_versions",
  "artifact_hashes", "session_id", "non_equivalence_note", "failure_code", "failure_detail", "evidence_path",
] as const;

export interface ParitySample {
  campaign_id: string;
  semantic_profile: Profile;
  cell_id: string;
  target: Target;
  device_model: string;
  os_version: string;
  abi: string;
  runtime: Runtime;
  browser: string;
  stack: Stack;
  frontend: "noir" | "circom";
  prover_backend: string;
  witness_backend: string;
  sample_kind: "warmup" | "measured" | "gap";
  sample_index: number | null;
  status: Status;
  prove_time_ms: number | null;
  proof_size_bytes: number | null;
  proving_payload_size_bytes: number | null;
  process_peak_memory_kib: number | null;
  valid_proof_accepted: boolean | null;
  tampered_proof_rejected: boolean | null;
  constraint_count: number | null;
  source_commits: string;
  package_versions: string;
  artifact_hashes: string;
  evidence_path: string;
  evidence_sha256: string;
  session_id: string;
  failure_code: string;
  failure_detail: string;
  semantic_equivalence_note: string;
}

export function cellId(profile: Profile, target: Target, stack: Stack) {
  return `${profile}__${target}__${stack}`;
}

export function expectedCellIds() {
  return PROFILES.flatMap((profile) => TARGETS.flatMap((target) => STACKS.map((stack) => cellId(profile, target, stack))));
}
