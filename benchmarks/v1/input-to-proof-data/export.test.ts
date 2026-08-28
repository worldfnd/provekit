import { describe, expect, test } from "bun:test";
import { normalizeIosReports, validateRows } from "./export";
import { CSV_COLUMNS, expectedSeries } from "./schema";

describe("input-to-proof schema", () => {
  test("preserves the old schema and appends cold/warm headline fields", () => {
    expect(CSV_COLUMNS.slice(-2)).toEqual(["timing_mode", "input_to_proof_time_ms"]);
    expect(new Set(CSV_COLUMNS).size).toBe(CSV_COLUMNS.length);
  });

  test("defines 72 full-campaign, 48 Mac+iPhone, and 24 Mac series", () => {
    expect(expectedSeries()).toHaveLength(72);
    expect(expectedSeries(["mac_chrome", "iphone_se_2022"])).toHaveLength(48);
    expect(expectedSeries(["mac_chrome"])).toHaveLength(24);
  });

  test("expands cold iPhone report arrays without changing warm reports", () => {
    const warm = { function: "warm" };
    const cold = Array.from({ length: 6 }, (_, invocation) => ({ invocation }));
    expect(normalizeIosReports(warm)).toEqual([warm]);
    expect(normalizeIosReports(cold)).toEqual(cold);
    expect(() => normalizeIosReports([cold[0], null])).toThrow("JSON object");
  });

  test("accepts one explicit failed gap with blank metrics as a complete logical series", () => {
    const id = "webauthn_closest_analogue__motorola_e15__circom_groth16__cold_local";
    const row = {
      hardware: "motorola_e15",
      circuit: "webauthn",
      prover: "circom_groth16",
      timing_mode: "cold_local",
      sample_kind: "gap",
      sample_index: null,
      status: "runtime_failed",
      failure_code: "out_of_memory",
      failure_detail: "mmap failed: Out of memory",
      prover_time_ms: null,
      total_time_ms: null,
      input_to_proof_time_ms: null,
      proof_size_bytes: null,
      circuit_size_bytes: null,
      peak_memory_mib: null,
    } as any;
    expect(() => validateRows([row], [id])).not.toThrow();
    expect(() => validateRows([{ ...row, proof_size_bytes: 0 }], [id])).toThrow("must be blank");
    expect(() => validateRows([{ ...row, failure_code: "timed_out" }], [id])).toThrow("invalid gap status");
    expect(() => validateRows([{ ...row, circuit: "oprf_nullifier" }], [
      "oprf_o2__motorola_e15__circom_groth16__cold_local",
    ])).toThrow("invalid gap status");
  });
});
