import { describe, expect, test } from "bun:test";
import { IOS_LANES, normalizeIosPrebuilt } from "./normalize-ios-prebuilt";

function fixture() {
  const functions: Record<string, any> = {};
  const entries: any[] = [];
  const names = [...new Set(IOS_LANES.flatMap((lane) => Object.values(lane.functions)))];
  for (const [index, name] of names.entries()) {
    functions[name!] = {
      spec: { iterations: 5, warmup: 1 },
      remote_run: { build_id: `build-${index}` },
      benchmark_results: {
        "iPhone SE 2022-15": [
          {
            function: name,
            samples: [1, 2, 3, 4, 5].map((n) => (index * 10 + n) * 1_000_000),
            custom_metrics: {
              sample_u64: {
                proof_size_bytes: [100, 101, 102, 103, 104, 105],
                prove_time_ns: [200, 201, 202, 203, 204, 205].map(
                  (value) => value * 1_000_000,
                ),
              },
              run_u64: {
                circuit_size_bytes: 400,
                proving_payload_size_bytes: 1000,
              },
            },
          },
        ],
      },
      performance_metrics: {
        "iPhone SE 2022-15": { memory: { peak_mb: 100 + index } },
      },
    };
    entries.push({
      function: name,
      iterations: 5,
      warmup: 1,
      artifacts: [
        {
          kind: "ios-app",
          path: `entries/${index}/app.ipa`,
          size: 1000 + index,
          sha256: `${index}`.padStart(64, "0"),
        },
      ],
    });
  }
  return {
    summary: { functions },
    manifest: { source_sha: "b".repeat(40), platform: "ios", entries },
  };
}

const options = {
  campaignId: "campaign",
  sourceCommit: "a".repeat(40),
  device: "iPhone SE 2022-15",
  osVersion: "iOS 15",
  evidencePath: "/evidence/summary.json",
  recordedAtUtc: "2026-07-29T12:00:00Z",
};

describe("normalizeIosPrebuilt", () => {
  test("emits one attested warmup and five measured rows for every iOS lane", () => {
    const { summary, manifest } = fixture();
    const records = normalizeIosPrebuilt(summary, manifest, options);
    expect(records).toHaveLength(IOS_LANES.length * 6);
    expect(records.filter((record) => record.sample_kind === "warmup")).toHaveLength(
      IOS_LANES.length,
    );
    expect(records.filter((record) => record.sample_kind === "measured")).toHaveLength(
      IOS_LANES.length * 5,
    );
    expect(
      records.every(
        (record) =>
          record.sample_kind !== "warmup" ||
          (record.prover_time_ms === null && record.total_time_ms === null),
      ),
    ).toBe(true);
    expect(records.every((record) => record.source_commit === options.sourceCommit)).toBe(true);
    expect(records.every((record) => record.source_commit !== fixture().manifest.source_sha)).toBe(
      true,
    );
    const provekitSample = records.find(
      (record) =>
        record.prover === "provekit_v1" &&
        record.circuit === "passport" &&
        record.sample_kind === "measured" &&
        record.sample_index === 1,
    );
    expect(provekitSample?.initialization_time_ms).toBeNull();
    expect(provekitSample?.verify_time_ms).toBeNull();
    expect(provekitSample?.total_time_ms).not.toBeNull();
    expect(provekitSample?.prover_time_ms).not.toBe(provekitSample?.total_time_ms);
    expect(provekitSample?.proof_size_bytes).toBe(101);
    expect(provekitSample?.prover_time_ms).toBe(201);
    expect(provekitSample?.artifact_size_bytes).toBe(1000);
    expect(provekitSample?.bundle_size_bytes).toBe(1000);
    expect(provekitSample?.circuit_size_bytes).toBe(400);
    expect(JSON.parse(provekitSample!.artifact_hashes)).toEqual({});
    const webauthnRapidsnark = records.find(
      (record) =>
        record.prover === "circom_groth16" &&
        record.circuit_variant === "privacy_ethereum_webauthn" &&
        record.sample_kind === "measured",
    );
    expect(webauthnRapidsnark?.prover_backend).toBe(
      "rapidsnark-groth16-native-single-thread",
    );
    expect(JSON.parse(webauthnRapidsnark!.package_versions).rapidsnark_threads).toBe(1);
  });

  test("rejects a result with fewer than five measured samples", () => {
    const { summary, manifest } = fixture();
    const first = Object.keys(summary.functions)[0]!;
    summary.functions[first].benchmark_results["iPhone SE 2022-15"][0].samples.pop();
    expect(() => normalizeIosPrebuilt(summary, manifest, options)).toThrow(
      /expected five measured samples/,
    );
  });

  test("uses zkey plus frozen WTNS for the iPhone Circom circuit payload", () => {
    const { summary, manifest } = fixture();
    const functionName =
      "provekit_v1_rapidsnark_mobile_webauthn::bench_webauthn_rapidsnark_prove";
    const metrics =
      summary.functions[functionName].benchmark_results["iPhone SE 2022-15"][0]
        .custom_metrics.run_u64;
    delete metrics.circuit_size_bytes;
    metrics.zkey_size_bytes = 1_733_145_772;
    metrics.witness_size_bytes = 109_218_412;
    metrics.proving_payload_size_bytes = 1_842_364_184;

    const records = normalizeIosPrebuilt(summary, manifest, options);
    const webauthnRapidsnark = records.find(
      (record) =>
        record.prover === "circom_groth16" &&
        record.circuit_variant === "privacy_ethereum_webauthn" &&
        record.sample_kind === "measured",
    );

    expect(webauthnRapidsnark?.circuit_size_bytes).toBe(1_842_364_184);
    expect(webauthnRapidsnark?.artifact_size_bytes).toBe(1_842_364_184);
    expect(webauthnRapidsnark?.bundle_size_bytes).toBe(1_842_364_184);
    expect(webauthnRapidsnark?.non_equivalence_note).toContain(
      "asset-size estimate: zkey plus frozen WTNS",
    );
  });

  test("emits an explicit evidence-backed gap for a missing lane", () => {
    const { summary, manifest } = fixture();
    delete summary.functions[
      "provekit_v1_rapidsnark_mobile_webauthn::bench_webauthn_rapidsnark_prove"
    ];
    manifest.entries = manifest.entries.filter(
      (entry) =>
        entry.function !==
        "provekit_v1_rapidsnark_mobile_webauthn::bench_webauthn_rapidsnark_prove",
    );

    const records = normalizeIosPrebuilt(summary, manifest, {
      ...options,
      gaps: [
        {
          circuit: "webauthn",
          circuit_variant: "privacy_ethereum_webauthn",
          prover: "circom_groth16",
          status: "build_failed",
          failure_code: "browserstack_ipa_too_large",
          failure_detail: "BrowserStack rejected the 1.18 GB IPA with HTTP 413.",
          evidence_path: "/tmp/http-413.txt",
        },
      ],
    });

    const gap = records.find(
      (record) =>
        record.circuit === "webauthn" &&
        record.prover === "circom_groth16",
    );
    expect(gap?.sample_kind).toBe("gap");
    expect(gap?.status).toBe("build_failed");
    expect(gap?.prover_time_ms).toBeNull();
  });
});
