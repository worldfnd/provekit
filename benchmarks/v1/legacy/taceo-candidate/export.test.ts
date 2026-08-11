import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import config from "./config.json";
import { buildCandidate, replacementSeries } from "./export";

const baseline = resolve(import.meta.dir, "../../input-to-proof-data/input-to-proof-samples.csv");
const scratch: string[] = [];
afterEach(() => scratch.splice(0).forEach((path) => rmSync(path, { recursive: true, force: true })));

const circuitByProfile = {
  passport_complete_age_check: ["passport_complete_age_check", "historical-monolithic-age-integrity", "9b2a6f37c67691eab4b0cec6c35e35c520e93285"],
  passport_p1: ["passport_age_integrity", "P1-matched-monolithic-RSA4096", "092621d721cfef9ff39b0787f5ba2c1f07eb6d95"],
  oprf_o2: ["oprf_nullifier", "O2-world-id-nullifier", "85aeeef539961cae5a63de794997b507a5975717"],
  webauthn_closest_analogue: ["webauthn", "closest-analogue", "0fb5b4aa1398281c2fd3dbe14db147e05b61f201"],
} as const;

function fixture(id: string) {
  const [profile, target, , timing_mode] = id.split("__") as [keyof typeof circuitByProfile, "iphone_se_2022" | "motorola_e15", string, "cold_local" | "warm_reuse"];
  const [name, variant, commit] = circuitByProfile[profile];
  return {
    schema_version: config.schema_version, series_id: id, profile, target, timing_mode,
    created_at_utc: "2026-08-11T12:00:00.000Z",
    environment: {
      hardware: target, device_model: target === "iphone_se_2022" ? "iPhone SE (2022)" : "moto e15",
      os_version: target === "iphone_se_2022" ? "18" : "14", abi: target === "iphone_se_2022" ? "arm64" : "armeabi-v7a",
      runtime: target === "iphone_se_2022" ? "ios_native" : "android_native", browser: "", session_id: `fixture-${id}`,
    },
    circuit: { name, variant, commit, constraint_count: 123 },
    backend: {
      frontend: "circom", prover_backend: config.prover_backend, witness_backend: config.witness_backend,
      source_commit: config.circom_helpers_commit, package_versions: config.package_versions,
    },
    artifacts: {
      proving_payload_size_bytes: 1000, artifact_size_bytes: 900, bundle_size_bytes: 1000,
      hashes: { zkey_sha256: "a".repeat(64), witness_graph_sha256: "b".repeat(64) },
    },
    public_outputs_sha256: "c".repeat(64), status: "ok", failure_code: "", failure_detail: "",
    samples: Array.from({ length: 6 }, (_, index) => ({
      sample_index: index, warmup: index === 0, status: "ok",
      initialization_time_ms: index === 0 ? 10 : 0, witness_time_ms: 20 + index, prover_time_ms: 30 + index,
      verify_time_ms: 1, total_time_ms: 50 + index * 2, input_to_proof_time_ms: 50 + index * 2,
      peak_memory_mib: index === 0 ? null : 100 + index, proof_size_bytes: 256,
      valid_proof_accepted: true, tampered_proof_rejected: true,
    })),
  };
}

function evidenceDir() {
  const dir = mkdtempSync(join(tmpdir(), "taceo-candidate-"));
  scratch.push(dir);
  for (const id of replacementSeries) writeFileSync(join(dir, `${id}.json`), JSON.stringify(fixture(id)));
  return dir;
}

describe("TACEO candidate exporter", () => {
  test("requires all 16 native Circom evidence files", async () => {
    const dir = evidenceDir();
    rmSync(join(dir, `${replacementSeries[0]}.json`));
    await expect(buildCandidate({ baselinePath: baseline, evidenceDir: dir, write: false })).rejects.toThrow(`missing TACEO evidence`);
  });

  test("replaces exactly 16 series and preserves the 72-series schema", async () => {
    const result = await buildCandidate({ baselinePath: baseline, evidenceDir: evidenceDir(), write: false });
    expect(result.replacementSeries).toHaveLength(16);
    expect(result.rows).toHaveLength(432);
    const taceo = result.rows.filter((row) => row.prover_backend === config.prover_backend);
    expect(taceo).toHaveLength(96);
    expect(taceo.every((row) => row.campaign_id === config.candidate_campaign_id)).toBe(true);
  });

  test("rejects estimates and unpinned backend evidence", async () => {
    const dir = evidenceDir();
    const id = replacementSeries[0];
    const bad = fixture(id) as any;
    bad.backend.prover_backend = "rapidsnark";
    writeFileSync(join(dir, `${id}.json`), JSON.stringify(bad));
    await expect(buildCandidate({ baselinePath: baseline, evidenceDir: dir, write: false })).rejects.toThrow("prover backend is not pinned");
  });

  test("accepts an explicit metric-free gap", async () => {
    const dir = evidenceDir();
    const id = replacementSeries.at(-1)!;
    const gap = fixture(id) as any;
    gap.status = "runtime_failed";
    gap.failure_code = "out_of_memory";
    gap.failure_detail = "allocator failed";
    gap.public_outputs_sha256 = "";
    gap.samples = [];
    writeFileSync(join(dir, `${id}.json`), JSON.stringify(gap));
    const result = await buildCandidate({ baselinePath: baseline, evidenceDir: dir, write: false });
    const row = result.rows.find((value) => value.attempt_id === `${id}-gap`)!;
    expect(row.status).toBe("runtime_failed");
    expect(row.input_to_proof_time_ms).toBeNull();
    expect(result.rows).toHaveLength(427);
  });
});
