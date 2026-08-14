import { describe, expect, test } from "bun:test";
import { mergeE15Reports } from "./merge-e15-reports";

function report(workload: string, status: string) {
  return {
    schema_version: 1,
    campaign_id: "campaign",
    sampling: { warmup: 1, measured: 5, sequential: true },
    device: { abi: "armeabi-v7a", zygote: "zygote32" },
    apk: { sha256: "a".repeat(64) },
    results: [{ workload, status }],
  };
}

describe("mergeE15Reports", () => {
  test("merges isolated retries in canonical workload order", () => {
    const merged = mergeE15Reports([
      { path: "passport.json", report: report("passport", "crashed") },
      { path: "oprf.json", report: report("oprf", "ok") },
    ]);
    expect(merged.results.map((result) => result.workload)).toEqual([
      "oprf",
      "passport",
    ]);
  });

  test("lets later isolated evidence replace a stale failure", () => {
    const merged = mergeE15Reports([
      { path: "old.json", report: report("oprf", "runtime_failed") },
      { path: "new.json", report: report("oprf", "ok") },
    ]);
    expect(merged.results[0]?.status).toBe("ok");
  });

  test("retains per-workload APK identity across isolated rebuilds", () => {
    const other = report("passport", "crashed");
    other.apk.sha256 = "b".repeat(64);
    const merged = mergeE15Reports([
      { path: "a.json", report: report("oprf", "ok") },
      { path: "b.json", report: other },
    ]);
    expect(merged.results[1]?.apk?.sha256).toBe("b".repeat(64));
  });

  test("rejects different campaign IDs without an explicit override", () => {
    const other = report("webauthn", "ok");
    other.campaign_id = "other-campaign";
    expect(() =>
      mergeE15Reports([
        { path: "one.json", report: report("oprf", "ok") },
        { path: "two.json", report: other },
      ]),
    ).toThrow("incompatible E15 report campaign");
  });

  test("uses an explicit campaign ID for compatible retained shards", () => {
    const other = report("webauthn", "ok");
    other.campaign_id = "other-campaign";
    const merged = mergeE15Reports(
      [
        { path: "one.json", report: report("oprf", "ok") },
        { path: "two.json", report: other },
      ],
      "frozen-campaign",
    );
    expect(merged.campaign_id).toBe("frozen-campaign");
    expect(merged.results.map((result) => result.workload)).toEqual([
      "oprf",
      "webauthn",
    ]);
  });
});
