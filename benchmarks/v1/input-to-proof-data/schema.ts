export const CAMPAIGN_ID = "input-to-proof-v1-20260807";
export const PROFILES = [
  "passport_complete_age_check",
  "passport_p1",
  "oprf_o2",
  "webauthn_closest_analogue",
] as const;
export const TARGETS = ["mac_chrome", "iphone_se_2022", "motorola_e15"] as const;
export const STACKS = ["provekit_v1", "noir_barretenberg", "circom_groth16"] as const;
export const TIMING_MODES = ["cold_local", "warm_reuse"] as const;
export const CSV_COLUMNS = [
  "campaign_id", "attempt_id", "recorded_at_utc", "hardware", "device_model", "os_version", "abi",
  "runtime", "browser", "circuit", "circuit_variant", "circuit_commit", "prover", "frontend",
  "prover_backend", "witness_backend", "sample_kind", "sample_index", "status",
  "initialization_time_ms", "witness_time_ms", "prover_time_ms", "verify_time_ms", "total_time_ms",
  "peak_memory_mib", "proof_size_bytes", "circuit_size_bytes", "artifact_size_bytes",
  "bundle_size_bytes", "constraint_count", "artifact_version", "source_commit", "package_versions",
  "artifact_hashes", "session_id", "non_equivalence_note", "failure_code", "failure_detail", "evidence_path",
  "timing_mode", "input_to_proof_time_ms",
] as const;

export type Profile = (typeof PROFILES)[number];
export type Target = (typeof TARGETS)[number];
export type Stack = (typeof STACKS)[number];
export type TimingMode = (typeof TIMING_MODES)[number];

export function seriesId(profile: Profile, target: Target, stack: Stack, mode: TimingMode) {
  return `${profile}__${target}__${stack}__${mode}`;
}

export function expectedSeries(targets: readonly Target[] = TARGETS) {
  return PROFILES.flatMap((profile) =>
    targets.flatMap((target) =>
      STACKS.flatMap((stack) =>
        TIMING_MODES.map((mode) => seriesId(profile, target, stack, mode)),
      ),
    ),
  );
}
