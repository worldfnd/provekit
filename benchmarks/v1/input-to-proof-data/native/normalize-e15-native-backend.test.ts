import { describe, expect, test } from "bun:test";
import {
  extractMobenchReport,
  normalizeE15NativeBackend,
} from "./normalize-e15-native-backend";

function fixture() {
  return {
    campaign_id: "campaign",
    recorded_at_utc: "2026-07-30T22:00:00Z",
    device: {
      model: "moto e15",
      os: "14",
      abi: "armeabi-v7a",
      zygote: "zygote32",
    },
    lane: {
      circuit: "passport" as const,
      circuit_variant: "passport_complete_age_check",
      circuit_commit: "a".repeat(40),
      prover: "noir_barretenberg" as const,
      prover_backend: "barretenberg-ultrahonk-native-armv7",
      witness_backend: "",
      artifact_version:
        "noir-v1.0.0-beta.19-barretenberg-rs-4.2.0-aztecnr-rc.2",
      package_versions: {
        mopro: "0.3.7",
        noir: "1.0.0-beta.19",
        barretenberg_rs: "4.2.0-aztecnr-rc.2",
      },
      artifact_hashes: { apk: "b".repeat(64) },
      evidence_path: "/evidence/passport.logcat.txt",
      report: {
        spec: {
          iterations: 5,
          warmup: 1,
          name: "bench_passport",
        },
        samples: [1, 2, 3, 4, 5].map((index) => ({
          duration_ns: index * 2_000_000,
          process_peak_memory_kb: index * 1024,
        })),
        custom_metrics: {
          run_u64: {
            circuit_size_bytes: 400,
            proving_payload_size_bytes: 1_000,
          },
          sample_u64: {
            prove_time_ns: [500_000, 600_000, 700_000, 800_000, 900_000, 1_000_000],
            proof_size_bytes: [100, 101, 102, 103, 104, 105],
          },
        },
      },
    },
  };
}

describe("normalizeE15NativeBackend", () => {
  test("emits one warmup and five exact-metric measured rows", () => {
    const records = normalizeE15NativeBackend(fixture(), "c".repeat(40));

    expect(records).toHaveLength(6);
    expect(records[0]?.sample_kind).toBe("measured");
    const first = records.find((record) => record.sample_index === 1);
    expect(first?.prover_time_ms).toBe(0.6);
    expect(first?.total_time_ms).toBe(2);
    expect(first?.proof_size_bytes).toBe(101);
    expect(first?.peak_memory_mib).toBe(1);
    expect(first?.artifact_size_bytes).toBe(1_000);
    expect(first?.bundle_size_bytes).toBe(1_000);
    expect(first?.circuit_size_bytes).toBe(400);
    expect(JSON.parse(first!.artifact_hashes)).toEqual({
      apk: "b".repeat(64),
    });
    const warmup = records.find((record) => record.sample_kind === "warmup");
    expect(warmup?.sample_index).toBe(0);
    expect(warmup?.prover_time_ms).toBeNull();
    expect(warmup?.peak_memory_mib).toBeNull();
  });

  test("reconstructs a chunked Mobench report from retained logcat", () => {
    const report = extractMobenchReport(
      [
        "I BenchRunner: BENCH_JSON_START",
        'I BenchRunner: BENCH_JSON_CHUNK {"spec":{"iterations":5,',
        'I BenchRunner: BENCH_JSON_CHUNK "warmup":1,"name":"bench"},"samples":[]}',
        "I BenchRunner: BENCH_JSON_END",
      ].join("\n"),
    );

    expect(report.spec).toEqual({
      iterations: 5,
      warmup: 1,
      name: "bench",
    });
  });
});
