import { describe, expect, test } from "bun:test";
import { generateE15NativeGaps } from "./generate-e15-native-gaps";

describe("generateE15NativeGaps", () => {
  test("emits the six non-ProveKit E15 cells from an attested 32-bit identity", () => {
    const records = generateE15NativeGaps(
      { model: "moto e15", os: "14", abi: "armeabi-v7a", zygote: "zygote32" },
      {
        campaignId: "campaign",
        sourceCommit: "a".repeat(40),
        recordedAtUtc: "2026-07-30T12:00:00.000Z",
        noirEvidencePath: "/tmp/noir-passport.log",
        circomEvidencePath: "/tmp/circom-build.log",
      },
    );
    expect(records).toHaveLength(6);
    expect(new Set(records.map((record) => record.prover))).toEqual(
      new Set(["noir_barretenberg", "circom_groth16"]),
    );
    expect(records.every((record) => record.sample_kind === "gap")).toBe(true);
    expect(
      records
        .filter((record) => record.prover === "circom_groth16")
        .every((record) => record.prover_backend.includes("arkworks")),
    ).toBe(true);
  });

  test("rejects a non-armv7 identity", () => {
    expect(() =>
      generateE15NativeGaps(
        { abi: "arm64-v8a", zygote: "zygote64" },
        {
          campaignId: "campaign",
          sourceCommit: "a".repeat(40),
          recordedAtUtc: "2026-07-30T12:00:00.000Z",
          noirEvidencePath: "/tmp/noir-passport.log",
          circomEvidencePath: "/tmp/circom-build.log",
        },
      ),
    ).toThrow("attested 32-bit target");
  });
});
