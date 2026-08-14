import { describe, expect, test } from "bun:test";
import { normalizeE15ProveKit } from "./normalize-e15-provekit";

function fixture() {
  return {
    campaign_id: "campaign",
    generated_at_utc: "2026-07-29T20:00:00Z",
    sampling: { warmup: 1, measured: 5, sequential: true },
    device: { model: "moto e15", os: "14", abi: "armeabi-v7a", zygote: "zygote32" },
    apk: { path: "/app.apk", sha256: "a".repeat(64), bytes: 1000 },
    results: (["passport", "webauthn", "oprf"] as const).map((workload) => ({
      workload,
      function: `bench_${workload}`,
      status: "ok" as const,
      report: {
        spec: { iterations: 5, warmup: 1 },
        samples: [1, 2, 3, 4, 5].map((value) => ({
          duration_ns: value * 1_000_000,
          process_peak_memory_kb: value * 1024,
        })),
        custom_metrics: {
          sample_u64: {
            prove_time_ns: [500_000, 500_000, 1_500_000, 2_500_000, 3_500_000, 4_500_000],
            proof_size_bytes: [100, 101, 102, 103, 104, 105],
          },
          run_u64: {
            prover_size_bytes: 700,
            input_size_bytes: 300,
            proving_payload_size_bytes: 1000,
          },
        },
      },
      evidence_path: `/evidence/${workload}.txt`,
    })),
  };
}

describe("normalizeE15ProveKit", () => {
  test("creates one attested warmup and five measured rows per workload", () => {
    const records = normalizeE15ProveKit(fixture(), "b".repeat(40));
    expect(records).toHaveLength(18);
    expect(records.filter((record) => record.sample_kind === "warmup")).toHaveLength(3);
    expect(records.filter((record) => record.sample_kind === "measured")).toHaveLength(15);
    const first = records.find(
      (record) => record.circuit === "passport" && record.sample_index === 1,
    );
    expect(first?.prover_time_ms).toBe(0.5);
    expect(first?.total_time_ms).toBe(1);
    expect(first?.proof_size_bytes).toBe(101);
    expect(first?.artifact_size_bytes).toBe(1000);
    expect(first?.bundle_size_bytes).toBe(1000);
    expect(first?.circuit_size_bytes).toBe(700);
    expect(JSON.parse(first!.artifact_hashes)).toEqual({});
  });

  test("keeps an opaque native panic as an explicit gap", () => {
    const input = fixture();
    input.results[2] = {
      ...input.results[2],
      status: "runtime_failed" as const,
      report: undefined as never,
      failure: { kind: "benchmark_error", message: "actual Rust panic" },
    } as never;
    const records = normalizeE15ProveKit(input, "b".repeat(40));
    expect(records.find((record) => record.circuit === "oprf")?.failure_detail).toBe(
      "actual Rust panic",
    );
  });

  test("labels the memory-constrained Passport variant and thread count", () => {
    const input = fixture();
    input.results = [
      {
        ...input.results[0]!,
        function:
          "bench_mobile::bench_passport_complete_age_check_e2e_single_thread",
      },
    ];
    const records = normalizeE15ProveKit(input, "b".repeat(40));
    expect(records[0]?.circuit_variant).toBe(
      "passport_complete_age_check_single_thread",
    );
    expect(JSON.parse(records[0]!.package_versions).rayon_threads).toBe(1);
  });
});
