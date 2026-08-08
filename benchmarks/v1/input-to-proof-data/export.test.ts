import { describe, expect, test } from "bun:test";
import { normalizeIosReports } from "./export";
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
});
