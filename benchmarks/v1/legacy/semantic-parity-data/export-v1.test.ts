import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportV1 } from "./export-v1";

describe("ProveKit V1 publication export", () => {
  test("rebuilds all nine V1 cells from hash-locked evidence", async () => {
    const directory = mkdtempSync(join(tmpdir(), "provekit-v1-export-"));
    const output = join(directory, "samples.csv");
    try {
      const rows = await exportV1(output);
      const cells = new Set(rows.map((row) => `${row.hardware}|${row.circuit}|${row.prover}`));
      const v1 = rows.filter((row) => row.prover === "provekit_v1");
      expect(rows).toHaveLength(162);
      expect(cells.size).toBe(27);
      expect(v1).toHaveLength(54);
      for (const cell of new Set(v1.map((row) => row.attempt_id.replace(/__(?:warmup|sample-\d+)$/, "")))) {
        const records = v1.filter((row) => row.attempt_id.startsWith(`${cell}__`));
        expect(records.filter((row) => row.sample_kind === "warmup")).toHaveLength(1);
        expect(records.filter((row) => row.sample_kind === "measured")).toHaveLength(5);
      }
      for (const row of v1.filter((candidate) => candidate.sample_kind === "measured")) {
        expect(row.prover_time_ms).toBeGreaterThan(0);
        expect(row.proof_size_bytes).toBeGreaterThan(0);
        expect(row.circuit_size_bytes).toBeGreaterThan(0);
        expect(row.artifact_size_bytes).toBeGreaterThan(0);
        expect(row.peak_memory_mib).toBeGreaterThan(0);
        expect(JSON.parse(row.artifact_hashes)).toHaveProperty("evidence");
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
