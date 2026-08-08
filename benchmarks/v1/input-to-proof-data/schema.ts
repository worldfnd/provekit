import { CSV_COLUMNS as PROOF_ONLY_COLUMNS } from "../semantic-parity-data/schema";

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
export const CSV_COLUMNS = [...PROOF_ONLY_COLUMNS, "timing_mode", "input_to_proof_time_ms"] as const;

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
